package domains

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A wildcard claim excludes every overlapping exact or wildcard claim, including
// those belonging to the same account. This prevents ambiguous authority.
func rejectOverlap(ctx context.Context, tx *sql.Tx, name string) error {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM custom_domains`)
	if err != nil {
		return err
	}
	defer rows.Close()
	base := strings.TrimPrefix(name, "*.")
	for rows.Next() {
		var other string
		if err := rows.Scan(&other); err != nil {
			return err
		}
		ob := strings.TrimPrefix(other, "*.")
		if (strings.HasPrefix(name, "*.") || strings.HasPrefix(other, "*.")) && (base == ob || strings.HasSuffix(base, "."+ob) || strings.HasSuffix(ob, "."+base)) {
			return status.Error(codes.AlreadyExists, "overlapping domain already claimed")
		}
	}
	return rows.Err()
}
func (r *Registry) proveWildcard(ctx context.Context, d *pb.Domain) error {
	// A unique CNAME is also valid proof; a generic edge CNAME is routing only.
	if cname, err := r.dns.LookupCNAME(ctx, d.Name); err == nil && strings.EqualFold(strings.TrimSuffix(cname, "."), d.CnameTarget) {
		return r.entitled(ctx, d)
	}
	resolver, ok := r.dns.(interface {
		LookupTXT(context.Context, string) ([]string, error)
	})
	if !ok {
		return fmt.Errorf("wildcard ownership requires TXT or unique CNAME proof")
	}
	records, err := resolver.LookupTXT(ctx, "_tunn-verification."+strings.TrimPrefix(d.Name, "*."))
	if err != nil {
		return err
	}
	for _, record := range records {
		if record == d.CnameTarget {
			return r.entitled(ctx, d)
		}
	}
	return fmt.Errorf("wildcard TXT ownership proof missing")
}
func (r *Registry) wildcardCertificate(ctx context.Context, parent *pb.Domain, hostname string) (*pb.CertificatePair, error) {
	name, err := NormalizeName(hostname, r.base)
	if err != nil || strings.HasPrefix(name, "*.") {
		return nil, status.Error(codes.NotFound, "concrete app hostname required")
	}
	// Only the owner's reserved names can cause an order, never arbitrary SNI.
	var owner string
	if err := r.db.QueryRowContext(ctx, `SELECT account_id FROM reserved_subdomains WHERE subdomain=?`, parent.Tunnel).Scan(&owner); err != nil || owner != parent.Owner {
		return nil, status.Error(codes.PermissionDenied, "app name must be reserved by domain owner")
	}
	select {
	case r.issueGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-r.issueGate }()
	// Recheck after waiting; deletion/reassignment and expired leases fail closed.
	current, err := r.Route(ctx, &pb.Domain{Name: name})
	if err != nil || current.Name != parent.Name || current.Owner != parent.Owner || current.CnameTarget != parent.CnameTarget {
		return nil, status.Error(codes.FailedPrecondition, "domain claim changed")
	}
	var cert, key []byte
	var expiry int64
	err = r.db.QueryRowContext(ctx, `SELECT certificate,key,not_after FROM wildcard_certificates WHERE name=? AND parent=? AND target=?`, name, parent.Name, parent.CnameTarget).Scan(&cert, &key, &expiry)
	if err == nil && expiry > r.now().Add(RenewBefore).Unix() {
		key, err = r.decrypt(name, key)
		return &pb.CertificatePair{CertificatePem: cert, KeyPem: key}, err
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	oldCert, oldKey, oldExpiry := cert, key, expiry
	if err := r.prove(ctx, parent); err != nil {
		r.fail(context.WithoutCancel(ctx), parent, "dns_verification_failed")
		return nil, status.Error(codes.FailedPrecondition, "DNS ownership proof lost")
	}
	// Count unsuccessful orders too, durably across restarts and relay nodes.
	var ownerAttempts, globalAttempts, recent int
	cutoff := r.now().Add(-time.Hour).Unix()
	if err := r.db.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(owner=?),0),coalesce(sum(name=? AND at>?),0) FROM domain_issue_attempts WHERE at>?`, parent.Owner, name, r.now().Add(-time.Minute).Unix(), cutoff).Scan(&globalAttempts, &ownerAttempts, &recent); err != nil {
		return nil, err
	}
	if ownerAttempts >= 10 || globalAttempts >= 100 || recent > 0 {
		if oldExpiry > r.now().Unix() {
			oldKey, e := r.decrypt(name, oldKey)
			return &pb.CertificatePair{CertificatePem: oldCert, KeyPem: oldKey}, e
		}
		return nil, status.Error(codes.ResourceExhausted, "certificate issuance rate limit; retry later")
	}
	if r.issuer == nil {
		return nil, status.Error(codes.Unavailable, "certificate issuer unavailable")
	}
	if _, err := r.db.ExecContext(ctx, `INSERT INTO domain_issue_attempts(owner,name,at) VALUES(?,?,?)`, parent.Owner, name, r.now().Unix()); err != nil {
		return nil, err
	}
	_, _ = r.db.ExecContext(ctx, `DELETE FROM domain_issue_attempts WHERE at<?`, cutoff)
	cert, key, err = r.issuer.Issue(ctx, name, func(ctx context.Context, token, value string) (func(), error) {
		if token == "" || strings.ContainsAny(token, "/\\") || len(token) > 256 || len(value) > 1024 {
			return nil, fmt.Errorf("invalid HTTP-01 challenge")
		}
		result, err := r.db.ExecContext(ctx, `INSERT INTO domain_challenges(name,target,token,value,expires) SELECT ?,target,?,?,? FROM custom_domains WHERE name=? AND owner=? AND target=? AND verified_until>? ON CONFLICT(name) DO UPDATE SET target=excluded.target,token=excluded.token,value=excluded.value,expires=excluded.expires`, name, token, value, r.now().Add(10*time.Minute).Unix(), parent.Name, parent.Owner, parent.CnameTarget, r.now().Unix())
		if err != nil {
			return nil, err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return nil, fmt.Errorf("claim changed")
		}
		return func() {
			_, _ = r.db.Exec(`DELETE FROM domain_challenges WHERE name=? AND target=? AND token=?`, name, parent.CnameTarget, token)
		}, nil
	})
	if err != nil {
		if proofErr := r.prove(ctx, parent); proofErr != nil {
			r.fail(context.WithoutCancel(ctx), parent, "dns_verification_failed")
		} else if oldExpiry > r.now().Unix() {
			oldKey, e := r.decrypt(name, oldKey)
			return &pb.CertificatePair{CertificatePem: oldCert, KeyPem: oldKey}, e
		}
		return nil, status.Error(codes.Unavailable, "certificate issuance failed")
	}
	parsed, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(parsed.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err := leaf.VerifyHostname(name); err != nil {
		return nil, err
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name || !r.now().Before(leaf.NotAfter) || r.now().Before(leaf.NotBefore) {
		return nil, fmt.Errorf("invalid issued certificate")
	}
	if err := r.prove(ctx, parent); err != nil {
		r.fail(context.WithoutCancel(ctx), parent, "dns_verification_failed")
		return nil, status.Error(codes.FailedPrecondition, "DNS ownership changed during issuance")
	}
	sealed, err := r.encrypt(name, key)
	if err != nil {
		return nil, err
	}
	result, err := r.db.ExecContext(ctx, `INSERT INTO wildcard_certificates(name,parent,target,certificate,key,not_after) SELECT ?,name,target,?,?,? FROM custom_domains WHERE name=? AND owner=? AND target=? AND verified_until>? ON CONFLICT(name) DO UPDATE SET parent=excluded.parent,target=excluded.target,certificate=excluded.certificate,key=excluded.key,not_after=excluded.not_after`, name, cert, sealed, leaf.NotAfter.Unix(), parent.Name, parent.Owner, parent.CnameTarget, r.now().Unix())
	if err != nil {
		return nil, err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return nil, status.Error(codes.Aborted, "claim changed during issuance")
	}
	return &pb.CertificatePair{CertificatePem: cert, KeyPem: key}, nil
}
func (r *Registry) refreshWildcardCertificates(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, `SELECT name FROM wildcard_certificates WHERE not_after<=? ORDER BY name`, r.now().Add(RenewBefore).Unix())
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		names = append(names, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		probe, cancel := context.WithTimeout(ctx, 3*time.Minute)
		_, _ = r.Certificate(probe, &pb.Domain{Name: name})
		cancel()
	}
	return ctx.Err()
}

func reserveWildcardApp(ctx context.Context, tx *sql.Tx, owner, name string, now time.Time) error {
	var existing string
	err := tx.QueryRowContext(ctx, `SELECT account_id FROM reserved_subdomains WHERE subdomain=?`, name).Scan(&existing)
	if err == nil {
		if existing != owner {
			return status.Error(codes.PermissionDenied, "app name belongs to another owner")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM reserved_subdomains WHERE account_id=?`, owner).Scan(&count); err != nil {
		return err
	}
	if count >= store.MaxReservedSubdomains {
		return status.Error(codes.ResourceExhausted, "reserved tunnel name limit reached")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO reserved_subdomains(subdomain,account_id,created_at) VALUES(?,?,?)`, name, owner, now.Unix())
	return err
}
