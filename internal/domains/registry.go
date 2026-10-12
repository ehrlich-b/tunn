// Package domains owns customer DNS bindings and ACME state on the login node.
package domains

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const DNSLease = 2 * time.Hour
const RenewBefore = 30 * 24 * time.Hour
const MaxDomains = 4

type DNSResolver interface {
	LookupCNAME(context.Context, string) (string, error)
}
type PresentChallenge func(context.Context, string, string) (func(), error)
type Issuer interface {
	Issue(context.Context, string, PresentChallenge) ([]byte, []byte, error)
}

type Backend interface {
	Add(context.Context, *pb.Domain) (*pb.Domain, error)
	List(context.Context, *pb.Owner) (*pb.DomainList, error)
	Verify(context.Context, *pb.Domain) (*pb.Domain, error)
	Delete(context.Context, *pb.Domain) (*emptypb.Empty, error)
	Route(context.Context, *pb.Domain) (*pb.Domain, error)
	Certificate(context.Context, *pb.Domain) (*pb.CertificatePair, error)
	Challenge(context.Context, *pb.ChallengeRequest) (*pb.ChallengeResponse, error)
}

type Registry struct {
	pb.UnimplementedDomainsServer
	db        *sql.DB
	base      string
	dns       DNSResolver
	issuer    Issuer
	seal      cipher.AEAD
	now       func() time.Time
	issueGate chan struct{}
}

func New(db *sql.DB, base string, key []byte, dns DNSResolver, issuer Issuer) (*Registry, error) {
	normalizedBase, nameErr := NormalizeName(base, "")
	if db == nil || len(key) != 32 || nameErr != nil || strings.HasPrefix(normalizedBase, "*.") || len(normalizedBase) > 217 {
		return nil, fmt.Errorf("domains require a database, relay DNS name and 32-byte encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	seal, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if dns == nil {
		dns = net.DefaultResolver
	}
	r := &Registry{db: db, base: normalizedBase, dns: dns, issuer: issuer, seal: seal, now: time.Now, issueGate: make(chan struct{}, 1)}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS custom_domains(
 name TEXT PRIMARY KEY,owner TEXT NOT NULL,tunnel TEXT NOT NULL,target TEXT UNIQUE NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending',verified_until INTEGER NOT NULL DEFAULT 0,
 certificate BLOB NOT NULL DEFAULT '',key BLOB NOT NULL DEFAULT '',not_after INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',pending_until INTEGER NOT NULL DEFAULT 0,proven INTEGER NOT NULL DEFAULT 0);
 CREATE INDEX IF NOT EXISTS custom_domains_owner ON custom_domains(owner);
 CREATE TABLE IF NOT EXISTS domain_challenges(name TEXT PRIMARY KEY,target TEXT NOT NULL,token TEXT NOT NULL,value TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS wildcard_certificates(name TEXT PRIMARY KEY,parent TEXT NOT NULL,target TEXT NOT NULL,certificate BLOB NOT NULL,key BLOB NOT NULL,not_after INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS domain_issue_attempts(owner TEXT NOT NULL,name TEXT NOT NULL,at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS domain_issue_attempts_owner ON domain_issue_attempts(owner,at);
 CREATE TABLE IF NOT EXISTS domain_settings(name TEXT PRIMARY KEY,value BLOB NOT NULL);`)
	if err != nil {
		return nil, err
	}
	if err := r.migrateClaims(); err != nil {
		return nil, err
	}
	if err := store.MigrateNamespaceNames(db); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *Registry) encrypt(name string, data []byte) ([]byte, error) {
	nonce := make([]byte, r.seal.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return r.seal.Seal(nonce, nonce, data, []byte(name)), nil
}
func (r *Registry) decrypt(name string, data []byte) ([]byte, error) {
	n := r.seal.NonceSize()
	if len(data) < n {
		return nil, fmt.Errorf("invalid encrypted key")
	}
	return r.seal.Open(nil, data[:n], data[n:], []byte(name))
}
func (r *Registry) Add(ctx context.Context, in *pb.Domain) (*pb.Domain, error) {
	name, err := NormalizeName(in.Name, r.base)
	wildcard := strings.HasPrefix(name, "*.")
	if err != nil || (!wildcard && (!ValidLabel(in.Tunnel) || common.IsReservedTunnelName(in.Tunnel))) || (wildcard && in.Tunnel != "" && (!ValidLabel(in.Tunnel) || common.IsReservedTunnelName(in.Tunnel))) || in.Owner == "" {
		return nil, status.Error(codes.InvalidArgument, "require a customer DNS name and reserved tunnel name")
	}
	reclaimTarget, reclaimProof := r.reclaimProof(ctx, name, in.Owner, in.Tunnel)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := r.expireClaims(ctx, tx); err != nil {
		return nil, err
	}
	if reclaimProof {
		var valid int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM domain_reclaim_requests WHERE name=? AND owner=? AND tunnel=? AND target=? AND expires>?`, name, in.Owner, in.Tunnel, reclaimTarget, r.now().Unix()).Scan(&valid); err != nil {
			return nil, err
		}
		reclaimProof = valid == 1
	}
	var plan string
	if err := tx.QueryRowContext(ctx, `SELECT plan FROM accounts WHERE id=?`, in.Owner).Scan(&plan); err != nil {
		return nil, err
	}
	if plan != "pro" {
		return nil, status.Error(codes.PermissionDenied, "custom domains require a Pro plan")
	}
	var owner, tunnel string
	err = tx.QueryRowContext(ctx, `SELECT owner,tunnel FROM custom_domains WHERE name=?`, name).Scan(&owner, &tunnel)
	if err == nil {
		if owner != in.Owner || (!wildcard && tunnel != in.Tunnel) {
			if err := r.reclaim(ctx, tx, name, in.Owner, in.Tunnel, reclaimTarget, reclaimProof); err != nil {
				return nil, err
			}
		} else {
			if wildcard && in.Tunnel != "" {
				if err := reserveWildcardApp(ctx, tx, name, in.Owner, in.Tunnel, r.now()); err != nil {
					return nil, err
				}
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return r.managementRead(ctx, name)
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM custom_domains WHERE owner=?)+(SELECT count(*) FROM domain_reclaim_requests WHERE owner=? AND name!=?)`, in.Owner, in.Owner, name).Scan(&count); err != nil {
		return nil, err
	}
	if count >= MaxDomains {
		return nil, status.Error(codes.ResourceExhausted, "custom domain limit reached")
	}
	if err := rejectOverlap(ctx, tx, name); err != nil {
		if status.Code(err) != codes.AlreadyExists {
			return nil, err
		}
		if err := r.reclaim(ctx, tx, name, in.Owner, in.Tunnel, reclaimTarget, reclaimProof); err != nil {
			return nil, err
		}
	}
	if !wildcard {
		// Reuse the central reservation table, including the same paid slot limit.
		err = tx.QueryRowContext(ctx, `SELECT account_id FROM reserved_subdomains WHERE subdomain=?`, in.Tunnel).Scan(&owner)
		if err == nil && owner != in.Owner {
			return nil, status.Error(codes.PermissionDenied, "tunnel name belongs to another account")
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if errors.Is(err, sql.ErrNoRows) {
			if err := store.CheckNewSharedReservation(in.Tunnel); err != nil {
				return nil, status.Error(codes.PermissionDenied, err.Error())
			}
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM reserved_subdomains WHERE account_id=?`, in.Owner).Scan(&count); err != nil {
				return nil, err
			}
			if count >= store.MaxReservedSubdomains {
				return nil, status.Error(codes.ResourceExhausted, "reserved tunnel name limit reached")
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO reserved_subdomains(subdomain,account_id,created_at) VALUES(?,?,?)`, in.Tunnel, in.Owner, r.now().Unix()); err != nil {
				return nil, err
			}
		}
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	target := "dv-" + hex.EncodeToString(token) + "." + r.base
	if reclaimProof {
		target = reclaimTarget
	}
	bindingTunnel := in.Tunnel
	if wildcard {
		bindingTunnel = ""
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO custom_domains(name,owner,tunnel,target,pending_until,proven) VALUES(?,?,?,?,?,?)`, name, in.Owner, bindingTunnel, target, r.now().Add(PendingClaimTTL).Unix(), reclaimProof); err != nil {
		return nil, err
	}
	if wildcard && in.Tunnel != "" {
		if err := reserveWildcardApp(ctx, tx, name, in.Owner, in.Tunnel, r.now()); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM domain_reclaim_requests WHERE name=? AND owner=?`, name, in.Owner); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.managementRead(ctx, name)
}

const domainColumns = `name,owner,tunnel,target,state,verified_until,not_after,last_error`

func scanDomain(row interface{ Scan(...any) error }) (*pb.Domain, error) {
	d := new(pb.Domain)
	err := row.Scan(&d.Name, &d.Owner, &d.Tunnel, &d.CnameTarget, &d.State, &d.VerifiedUntil, &d.CertificateExpires, &d.LastError)
	return d, err
}
func (r *Registry) read(ctx context.Context, name string) (*pb.Domain, error) {
	return scanDomain(r.db.QueryRowContext(ctx, `SELECT `+domainColumns+` FROM custom_domains WHERE name=?`, name))
}
func (r *Registry) List(ctx context.Context, in *pb.Owner) (*pb.DomainList, error) {
	if in.Owner == "" {
		return nil, status.Error(codes.InvalidArgument, "owner required")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+domainColumns+` FROM custom_domains WHERE owner=? ORDER BY name`, in.Owner)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := new(pb.DomainList)
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out.Domains = append(out.Domains, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, d := range out.Domains {
		if err := r.appNames(ctx, d); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (r *Registry) owned(ctx context.Context, in *pb.Domain) (*pb.Domain, error) {
	name, err := NormalizeName(in.Name, r.base)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid domain")
	}
	d, err := r.read(ctx, name)
	if errors.Is(err, sql.ErrNoRows) || err == nil && d.Owner != in.Owner {
		return nil, status.Error(codes.NotFound, "domain not found")
	}
	return d, err
}
func (r *Registry) entitled(ctx context.Context, d *pb.Domain) error {
	if strings.HasPrefix(d.Name, "*.") {
		var plan string
		if err := r.db.QueryRowContext(ctx, `SELECT plan FROM accounts WHERE id=?`, d.Owner).Scan(&plan); err != nil {
			return err
		}
		if plan != "pro" {
			return status.Error(codes.PermissionDenied, "domain entitlement lost")
		}
		return nil
	}
	var plan, owner string
	err := r.db.QueryRowContext(ctx, `SELECT a.plan,s.account_id FROM accounts a JOIN reserved_subdomains s ON s.subdomain=? WHERE a.id=?`, d.Tunnel, d.Owner).Scan(&plan, &owner)
	if err != nil {
		return err
	}
	if plan != "pro" || owner != d.Owner {
		return status.Error(codes.PermissionDenied, "domain entitlement or tunnel ownership lost")
	}
	return nil
}
func (r *Registry) prove(ctx context.Context, d *pb.Domain) error {
	if strings.HasPrefix(d.Name, "*.") {
		return r.proveWildcard(ctx, d)
	}
	resolved, err := r.dns.LookupCNAME(ctx, d.Name)
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %w", err)
	}
	if !strings.EqualFold(strings.TrimSuffix(resolved, "."), d.CnameTarget) {
		return fmt.Errorf("CNAME does not match the unique verification target")
	}
	return r.entitled(ctx, d)
}
func (r *Registry) fail(ctx context.Context, d *pb.Domain, reason string) {
	_, _ = r.db.ExecContext(ctx, `UPDATE custom_domains SET state=?,verified_until=0,last_error=? WHERE name=? AND owner=? AND target=?`, reason, reason, d.Name, d.Owner, d.CnameTarget)
}
func (r *Registry) Verify(ctx context.Context, in *pb.Domain) (*pb.Domain, error) {
	select {
	case r.issueGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-r.issueGate }()
	d, err := r.owned(ctx, in)
	if err != nil {
		return nil, err
	}
	if err := r.prove(ctx, d); err != nil {
		r.fail(context.WithoutCancel(ctx), d, "dns_verification_failed")
		return nil, status.Error(codes.FailedPrecondition, "DNS verification failed; set the exact CNAME target and retry")
	}
	if err := r.promoteClaim(ctx, d); err != nil {
		return nil, err
	}
	if strings.HasPrefix(d.Name, "*.") {
		result, err := r.db.ExecContext(ctx, `UPDATE custom_domains SET state='ready',verified_until=?,last_error='' WHERE name=? AND owner=? AND target=?`, r.now().Add(DNSLease).Unix(), d.Name, d.Owner, d.CnameTarget)
		if err != nil {
			return nil, err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return nil, status.Error(codes.Aborted, "domain claim changed during verification")
		}
		return r.read(ctx, d.Name)
	}
	if d.CertificateExpires > r.now().Add(RenewBefore).Unix() {
		return r.refreshConcreteLease(ctx, d, "")
	}
	if err := r.admitIssuance(ctx, d.Owner, d.Name); err != nil {
		if d.CertificateExpires > r.now().Unix() {
			if _, refreshErr := r.refreshConcreteLease(ctx, d, "certificate_issuance_deferred"); refreshErr != nil {
				return nil, refreshErr
			}
		}
		return nil, err
	}
	certPEM, keyPEM, err := r.issuer.Issue(ctx, d.Name, func(ctx context.Context, token, value string) (func(), error) {
		if token == "" || strings.ContainsAny(token, "/\\") || len(token) > 256 || len(value) > 1024 {
			return nil, fmt.Errorf("invalid HTTP-01 challenge")
		}
		// A deleted or replaced claim cannot acquire a challenge from an old order.
		result, err := r.db.ExecContext(ctx, `INSERT INTO domain_challenges(name,target,token,value,expires)
 SELECT name,target,?,?,? FROM custom_domains WHERE name=? AND owner=? AND target=? AND EXISTS(SELECT 1 FROM accounts a JOIN reserved_subdomains s ON s.subdomain=custom_domains.tunnel WHERE a.id=custom_domains.owner AND a.plan='pro' AND s.account_id=a.id)
 ON CONFLICT(name) DO UPDATE SET target=excluded.target,token=excluded.token,value=excluded.value,expires=excluded.expires`, token, value, r.now().Add(10*time.Minute).Unix(), d.Name, d.Owner, d.CnameTarget)
		if err != nil {
			return nil, err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return nil, fmt.Errorf("domain claim changed")
		}
		return func() {
			_, _ = r.db.Exec(`DELETE FROM domain_challenges WHERE name=? AND target=? AND token=?`, d.Name, d.CnameTarget, token)
		}, nil
	})
	if err != nil {
		// Issuance may take minutes. Recheck DNS before extending the lease
		// for an old certificate, just as successful issuance does below.
		if proofErr := r.prove(ctx, d); proofErr != nil {
			r.fail(context.WithoutCancel(ctx), d, "dns_verification_failed")
		} else if d.CertificateExpires > r.now().Unix() {
			_, _ = r.refreshConcreteLease(ctx, d, "certificate_issuance_failed")
		} else {
			r.fail(context.WithoutCancel(ctx), d, "certificate_issuance_failed")
		}
		return nil, status.Error(codes.Unavailable, "certificate issuance failed; retry verification")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err := leaf.VerifyHostname(d.Name); err != nil {
		return nil, err
	}
	if !r.now().Before(leaf.NotAfter) || r.now().Before(leaf.NotBefore) || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != d.Name {
		return nil, fmt.Errorf("issuer returned an invalid domain certificate")
	}
	if err := r.prove(ctx, d); err != nil {
		r.fail(context.WithoutCancel(ctx), d, "dns_verification_failed")
		return nil, status.Error(codes.FailedPrecondition, "DNS ownership changed during issuance")
	}
	encrypted, err := r.encrypt(d.Name, keyPEM)
	if err != nil {
		return nil, err
	}
	result, err := r.db.ExecContext(ctx, `UPDATE custom_domains SET state='ready',verified_until=?,certificate=?,key=?,not_after=?,last_error='' WHERE name=? AND owner=? AND target=? AND EXISTS(SELECT 1 FROM accounts a JOIN reserved_subdomains s ON s.subdomain=custom_domains.tunnel WHERE a.id=custom_domains.owner AND a.plan='pro' AND s.account_id=a.id)`, r.now().Add(DNSLease).Unix(), certPEM, encrypted, leaf.NotAfter.Unix(), d.Name, d.Owner, d.CnameTarget)
	if err != nil {
		return nil, err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return nil, status.Error(codes.Aborted, "domain claim changed during issuance")
	}
	return r.read(ctx, d.Name)
}
func (r *Registry) Delete(ctx context.Context, in *pb.Domain) (*emptypb.Empty, error) {
	d, err := r.owned(ctx, in)
	if err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM wildcard_certificates WHERE parent=? AND target=?`, d.Name, d.CnameTarget); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM domain_challenges WHERE target=?`, d.CnameTarget); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM custom_domains WHERE name=? AND owner=? AND target=?`, d.Name, d.Owner, d.CnameTarget); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, tx.Commit()
}
func (r *Registry) Route(ctx context.Context, in *pb.Domain) (*pb.Domain, error) {
	name, err := NormalizeName(in.Name, r.base)
	if err != nil {
		return nil, status.Error(codes.NotFound, "unknown customer domain")
	}
	d, err := r.read(ctx, name)
	wildcard := false
	if errors.Is(err, sql.ErrNoRows) {
		if dot := strings.IndexByte(name, '.'); dot > 0 {
			d, err = r.read(ctx, "*."+name[dot+1:])
			wildcard = err == nil
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "unknown customer domain")
	}
	if err != nil {
		return nil, err
	}
	if d.State != "ready" || d.VerifiedUntil <= r.now().Unix() || !strings.HasPrefix(d.Name, "*.") && d.CertificateExpires <= r.now().Unix() {
		return nil, status.Error(codes.FailedPrecondition, "domain DNS or certificate is not ready")
	}
	if err := r.entitled(ctx, d); err != nil {
		return nil, err
	}
	if wildcard {
		label := strings.SplitN(name, ".", 2)[0]
		if !ValidLabel(label) || common.IsReservedTunnelName(label) {
			return nil, status.Error(codes.NotFound, "invalid app name")
		}
		if err := r.db.QueryRowContext(ctx, `SELECT n.tunnel FROM namespace_app_names n JOIN custom_domains d ON d.name=n.parent AND d.target=n.target WHERE n.parent=? AND n.target=? AND n.label=? AND d.owner=? AND `+appAuthority, d.Name, d.CnameTarget, label, d.Owner).Scan(&d.Tunnel); err != nil {
			return nil, status.Error(codes.PermissionDenied, "app name must be registered in this namespace by its owner")
		}
	}
	return d, nil
}
func (r *Registry) Certificate(ctx context.Context, in *pb.Domain) (*pb.CertificatePair, error) {
	d, err := r.Route(ctx, in)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(d.Name, "*.") {
		return r.wildcardCertificate(ctx, d, in.Name)
	}
	var cert, key []byte
	// Recheck current authority in the key read; Route may precede revocation.
	now := r.now().Unix()
	err = r.db.QueryRowContext(ctx, `SELECT certificate,key FROM custom_domains WHERE name=? AND owner=? AND target=? AND state='ready' AND verified_until>? AND not_after>? AND EXISTS(SELECT 1 FROM accounts a JOIN reserved_subdomains s ON s.subdomain=custom_domains.tunnel WHERE a.id=custom_domains.owner AND a.plan='pro' AND s.account_id=a.id)`, d.Name, d.Owner, d.CnameTarget, now, now).Scan(&cert, &key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Error(codes.FailedPrecondition, "app reservation or domain authority changed")
	}
	if err != nil {
		return nil, err
	}
	key, err = r.decrypt(d.Name, key)
	if err != nil {
		return nil, err
	}
	return &pb.CertificatePair{CertificatePem: cert, KeyPem: key}, nil
}
func (r *Registry) Challenge(ctx context.Context, in *pb.ChallengeRequest) (*pb.ChallengeResponse, error) {
	name, err := NormalizeName(in.Name, r.base)
	if err != nil {
		return nil, status.Error(codes.NotFound, "challenge not found")
	}
	var value string
	err = r.db.QueryRowContext(ctx, `SELECT c.value FROM domain_challenges c JOIN custom_domains d ON d.target=c.target JOIN accounts a ON a.id=d.owner WHERE c.name=? AND c.token=? AND c.expires>? AND a.plan='pro' AND ((d.tunnel!='' AND EXISTS(SELECT 1 FROM reserved_subdomains s WHERE s.account_id=d.owner AND s.subdomain=d.tunnel)) OR (d.tunnel='' AND d.state='ready' AND d.verified_until>? AND d.name='*.'||substr(c.name,instr(c.name,'.')+1) AND EXISTS(SELECT 1 FROM namespace_app_names n WHERE n.parent=d.name AND n.target=d.target AND n.label=substr(c.name,1,instr(c.name,'.')-1) AND `+appAuthority+`)))`, name, in.Token, r.now().Unix(), r.now().Unix()).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "challenge not found")
	}
	return &pb.ChallengeResponse{Body: value}, err
}

// Refresh rechecks DNS hourly, renews 30 days before expiry, and leaves no stale
// routing lease after a DNS error. Only the login node runs this worker.
func (r *Registry) Refresh(ctx context.Context) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := r.expireClaims(ctx, tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+domainColumns+` FROM custom_domains WHERE not_after>0 OR name LIKE '*.%' ORDER BY name`)
	if err != nil {
		return err
	}
	var domains []*pb.Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			_ = rows.Close()
			return err
		}
		domains = append(domains, d)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, d := range domains {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		probe, cancel := context.WithTimeout(ctx, 3*time.Minute)
		_, _ = r.Verify(probe, d)
		cancel()
	}
	return r.refreshWildcardCertificates(ctx)
}
func (r *Registry) Run(ctx context.Context) {
	_ = r.Refresh(ctx)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = r.Refresh(ctx)
		}
	}
}
