package domains

import (
	"context"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Every concrete/app order, including failures and renewals, reserves the same
// durable budget before contacting the issuer. Callers hold issueGate.
func (r *Registry) admitIssuance(ctx context.Context, owner, name string) error {
	if r.issuer == nil {
		return status.Error(codes.Unavailable, "certificate issuer unavailable")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := r.now()
	cutoff := now.Add(-time.Hour).Unix()
	var global, owned, recent int
	if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(owner=?),0),coalesce(sum(name=? AND at>?),0) FROM domain_issue_attempts WHERE at>?`, owner, name, now.Add(-time.Minute).Unix(), cutoff).Scan(&global, &owned, &recent); err != nil {
		return err
	}
	if owned >= 10 || global >= 100 || recent > 0 {
		return status.Error(codes.ResourceExhausted, "certificate issuance rate limit; retry later")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO domain_issue_attempts(owner,name,at) VALUES(?,?,?)`, owner, name, now.Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM domain_issue_attempts WHERE at<=?`, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Registry) refreshConcreteLease(ctx context.Context, d *pb.Domain, lastError string) (*pb.Domain, error) {
	result, err := r.db.ExecContext(ctx, `UPDATE custom_domains SET state='ready',verified_until=?,last_error=? WHERE name=? AND owner=? AND target=? AND not_after>? AND EXISTS(SELECT 1 FROM accounts a JOIN reserved_subdomains s ON s.subdomain=custom_domains.tunnel WHERE a.id=custom_domains.owner AND a.plan='pro' AND s.account_id=a.id)`, r.now().Add(DNSLease).Unix(), lastError, d.Name, d.Owner, d.CnameTarget, r.now().Unix())
	if err != nil {
		return nil, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, status.Error(codes.Aborted, "domain claim or reservation changed")
	}
	return r.read(ctx, d.Name)
}
