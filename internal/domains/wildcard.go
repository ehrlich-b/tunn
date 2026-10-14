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
	for rows.Next() {
		var other string
		if err := rows.Scan(&other); err != nil {
			return err
		}
		if overlaps(name, other) {
			return status.Error(codes.AlreadyExists, "overlapping domain already claimed")
		}
	}
	return rows.Err()
}
func (r *Registry) proveWildcard(ctx context.Context, d *pb.Domain) error {
	if err := r.wildcardDNSProof(ctx, d); err != nil {
		return err
	}
	return r.entitled(ctx, d)
}
func (r *Registry) wildcardDNSProof(ctx context.Context, d *pb.Domain) error {
	// A unique CNAME is also valid proof; a generic edge CNAME is routing only.
	if cname, err := r.dns.LookupCNAME(ctx, d.Name); err == nil && strings.EqualFold(strings.TrimSuffix(cname, "."), d.CnameTarget) {
		return nil
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
			return nil
		}
	}
	return fmt.Errorf("wildcard TXT ownership proof missing")
}
func (r *Registry) wildcardCertificate(ctx context.Context, parent *pb.Domain, hostname string) (*pb.CertificatePair, error) {
	name, err := NormalizeName(hostname, r.base)
	if err != nil || strings.HasPrefix(name, "*.") {
		return nil, status.Error(codes.NotFound, "concrete app hostname required")
	}
	select {
	case r.issueGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-r.issueGate }()
	// Recheck after waiting; deletion/reassignment and expired leases fail closed.
	current, err := r.Route(ctx, &pb.Domain{Name: name})
	if err != nil || current.Name != parent.Name || current.Owner != parent.Owner || current.CnameTarget != parent.CnameTarget || current.Tunnel != parent.Tunnel {
		return nil, status.Error(codes.FailedPrecondition, "domain claim changed")
	}
	var cert, key []byte
	var expiry int64
	err = r.db.QueryRowContext(ctx, `SELECT certificate,key,not_after FROM wildcard_certificates WHERE name=? AND parent=? AND target=?`, name, parent.Name, parent.CnameTarget).Scan(&cert, &key, &expiry)
	if err == nil && expiry > r.now().Add(RenewBefore).Unix() {
		return r.cachedWildcard(ctx, parent, name)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	oldExpiry := expiry
	if err := r.prove(ctx, parent); err != nil {
		r.fail(context.WithoutCancel(ctx), parent, "dns_verification_failed")
		return nil, status.Error(codes.FailedPrecondition, "DNS ownership proof lost")
	}
	if err := r.admitIssuance(ctx, parent.Owner, name); err != nil {
		if oldExpiry > r.now().Unix() {
			return r.cachedWildcard(ctx, parent, name)
		}
		return nil, err
	}
	cert, key, err = r.issuer.Issue(ctx, name, func(ctx context.Context, token, value string) (func(), error) {
		if token == "" || strings.ContainsAny(token, "/\\") || len(token) > 256 || len(value) > 1024 {
			return nil, fmt.Errorf("invalid HTTP-01 challenge")
		}
		result, err := r.db.ExecContext(ctx, `INSERT INTO domain_challenges(name,target,token,value,expires) SELECT ?,target,?,?,? FROM custom_domains d WHERE name=? AND owner=? AND target=? AND state='ready' AND verified_until>? AND EXISTS(SELECT 1 FROM accounts a JOIN namespace_app_names n ON n.parent=d.name AND n.target=d.target WHERE a.id=d.owner AND a.plan='pro' AND n.tunnel=? AND `+appAuthority+`) ON CONFLICT(name) DO UPDATE SET target=excluded.target,token=excluded.token,value=excluded.value,expires=excluded.expires`, name, token, value, r.now().Add(10*time.Minute).Unix(), parent.Name, parent.Owner, parent.CnameTarget, r.now().Unix(), parent.Tunnel)
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
			return r.cachedWildcard(ctx, parent, name)
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
	result, err := r.db.ExecContext(ctx, `INSERT INTO wildcard_certificates(name,parent,target,certificate,key,not_after) SELECT ?,name,target,?,?,? FROM custom_domains d WHERE name=? AND owner=? AND target=? AND state='ready' AND verified_until>? AND EXISTS(SELECT 1 FROM accounts a JOIN namespace_app_names n ON n.parent=d.name AND n.target=d.target WHERE a.id=d.owner AND a.plan='pro' AND n.tunnel=? AND `+appAuthority+`) ON CONFLICT(name) DO UPDATE SET parent=excluded.parent,target=excluded.target,certificate=excluded.certificate,key=excluded.key,not_after=excluded.not_after`, name, cert, sealed, leaf.NotAfter.Unix(), parent.Name, parent.Owner, parent.CnameTarget, r.now().Unix(), parent.Tunnel)
	if err != nil {
		return nil, err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return nil, status.Error(codes.Aborted, "claim changed during issuance")
	}
	return r.cachedWildcard(ctx, parent, name)
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

// Read the key under the current reservation predicate, including cached and
// failed-renewal responses; an earlier Route check cannot authorize this read.
func (r *Registry) cachedWildcard(ctx context.Context, parent *pb.Domain, name string) (*pb.CertificatePair, error) {
	var cert, key []byte
	err := r.db.QueryRowContext(ctx, `SELECT c.certificate,c.key FROM wildcard_certificates c JOIN custom_domains d ON d.name=c.parent AND d.target=c.target JOIN accounts a ON a.id=d.owner JOIN namespace_app_names n ON n.parent=d.name AND n.target=d.target WHERE c.name=? AND d.name=? AND d.owner=? AND d.target=? AND d.state='ready' AND d.verified_until>? AND a.plan='pro' AND n.tunnel=? AND `+appAuthority+` AND c.not_after>?`, name, parent.Name, parent.Owner, parent.CnameTarget, r.now().Unix(), parent.Tunnel, r.now().Unix()).Scan(&cert, &key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Error(codes.FailedPrecondition, "namespace app name or domain authority changed")
	}
	if err != nil {
		return nil, err
	}
	key, err = r.decrypt(name, key)
	if err != nil {
		return nil, err
	}
	return &pb.CertificatePair{CertificatePem: cert, KeyPem: key}, nil
}
