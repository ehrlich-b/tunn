package domains

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const PendingClaimTTL = 24 * time.Hour

func (r *Registry) migrateClaims() error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`PRAGMA table_info(custom_domains)`)
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var id, nullable, pk int
		var name, kind string
		var value any
		if err := rows.Scan(&id, &name, &kind, &nullable, &value, &pk); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, column := range []string{"pending_until", "proven"} {
		if !columns[column] {
			if _, err := tx.Exec(`ALTER TABLE custom_domains ADD COLUMN ` + column + ` INTEGER NOT NULL DEFAULT 0`); err != nil {
				return err
			}
		}
	}
	// Preserve historical verified owners with persisted readiness or certificates.
	if !columns["proven"] {
		if _, err := tx.Exec(`UPDATE custom_domains SET proven=1 WHERE state='ready' OR verified_until>0 OR not_after>0`); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`UPDATE custom_domains SET pending_until=? WHERE proven=0 AND pending_until=0;
 CREATE TABLE IF NOT EXISTS domain_reclaim_requests(name TEXT NOT NULL,owner TEXT NOT NULL,tunnel TEXT NOT NULL,target TEXT UNIQUE NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(name,owner));`, r.now().Add(PendingClaimTTL).Unix())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Registry) expireClaims(ctx context.Context, tx *sql.Tx) error {
	for _, query := range []string{
		`DELETE FROM domain_challenges WHERE target IN (SELECT target FROM custom_domains WHERE proven=0 AND pending_until<=?)`,
		`DELETE FROM wildcard_certificates WHERE target IN (SELECT target FROM custom_domains WHERE proven=0 AND pending_until<=?)`,
		`DELETE FROM custom_domains WHERE proven=0 AND pending_until<=?`,
		`DELETE FROM domain_reclaim_requests WHERE expires<=?`,
	} {
		if _, err := tx.ExecContext(ctx, query, r.now().Unix()); err != nil {
			return err
		}
	}
	return nil
}

func overlaps(name, other string) bool {
	base, ob := strings.TrimPrefix(name, "*."), strings.TrimPrefix(other, "*.")
	return name == other || (strings.HasPrefix(name, "*.") || strings.HasPrefix(other, "*.")) && (base == ob || strings.HasSuffix(base, "."+ob) || strings.HasSuffix(ob, "."+base))
}

// Competing proof requests do not replace the incumbent until their fresh proof
// succeeds; the management error supplies the request's unique DNS target.
func (r *Registry) reclaimProof(ctx context.Context, name, owner, tunnel string) (string, bool) {
	var target string
	err := r.db.QueryRowContext(ctx, `SELECT target FROM domain_reclaim_requests WHERE name=? AND owner=? AND tunnel=? AND expires>?`, name, owner, tunnel, r.now().Unix()).Scan(&target)
	if err != nil {
		return "", false
	}
	d := &pb.Domain{Name: name, Owner: owner, Tunnel: tunnel, CnameTarget: target}
	return target, r.proveDNS(ctx, d) == nil
}

func (r *Registry) reclaim(ctx context.Context, tx *sql.Tx, name, owner, tunnel, target string, proof bool) error {
	rows, err := tx.QueryContext(ctx, `SELECT name,proven FROM custom_domains`)
	if err != nil {
		return err
	}
	var victims []string
	protected := false
	for rows.Next() {
		var other string
		var proven bool
		if err := rows.Scan(&other, &proven); err != nil {
			rows.Close()
			return err
		}
		if overlaps(name, other) {
			if proven {
				protected = true
			}
			victims = append(victims, other)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if protected {
		return status.Error(codes.AlreadyExists, "overlapping domain has a verified owner")
	}
	if proof {
		var valid int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM domain_reclaim_requests WHERE name=? AND owner=? AND tunnel=? AND target=? AND expires>?`, name, owner, tunnel, target, r.now().Unix()).Scan(&valid); err != nil {
			return err
		}
		if valid != 1 {
			return status.Error(codes.Aborted, "competing proof request changed")
		}
		for _, victim := range victims {
			if _, err := tx.ExecContext(ctx, `DELETE FROM custom_domains WHERE name=? AND proven=0`, victim); err != nil {
				return err
			}
		}
		return nil
	}
	// Bound pending proof requests just like normal claims, per account.
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM custom_domains WHERE owner=?)+(SELECT count(*) FROM domain_reclaim_requests WHERE owner=? AND name!=?)`, owner, owner, name).Scan(&count); err != nil {
		return err
	}
	if count >= MaxDomains {
		return status.Error(codes.ResourceExhausted, "custom domain proof request limit reached")
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	target = "dv-" + hex.EncodeToString(token) + "." + r.base
	if _, err := tx.ExecContext(ctx, `INSERT INTO domain_reclaim_requests VALUES(?,?,?,?,?) ON CONFLICT(name,owner) DO NOTHING`, name, owner, tunnel, target, r.now().Add(PendingClaimTTL).Unix()); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT target FROM domain_reclaim_requests WHERE name=? AND owner=?`, name, owner).Scan(&target); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	record := name
	kind := "CNAME"
	if strings.HasPrefix(name, "*.") {
		record = "_tunn-verification." + strings.TrimPrefix(name, "*.")
		kind = "TXT"
	}
	return status.Errorf(codes.AlreadyExists, "unverified claim: prove ownership with %s %s = %s and retry add within 24 hours", kind, record, target)
}

func (r *Registry) proveDNS(ctx context.Context, d *pb.Domain) error {
	if strings.HasPrefix(d.Name, "*.") {
		return r.wildcardDNSProof(ctx, d)
	}
	resolved, err := r.dns.LookupCNAME(ctx, d.Name)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSuffix(resolved, "."), d.CnameTarget) {
		return fmt.Errorf("unique CNAME proof missing")
	}
	return nil
}

func (r *Registry) promoteClaim(ctx context.Context, d *pb.Domain) error {
	result, err := r.db.ExecContext(ctx, `UPDATE custom_domains SET proven=1 WHERE name=? AND owner=? AND target=? AND (proven=1 OR pending_until>?)`, d.Name, d.Owner, d.CnameTarget, r.now().Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return status.Error(codes.Aborted, "domain proof request expired or changed")
	}
	return nil
}
