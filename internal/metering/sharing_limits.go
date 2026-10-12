package metering

import (
	"context"
	"database/sql"
	"errors"

	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

var ErrSharingRate error = &admissionError{message: "sharing mutation rate exceeded", reason: "SHARING_RATE"}

func (s *Store) grantCapacity(ctx context.Context, tx *sql.Tx, owner, resource string, person bool) error {
	var global, owned int
	if err := tx.QueryRowContext(ctx, `SELECT count(*),count(CASE WHEN owner=? THEN 1 END) FROM meter_grants`, owner).Scan(&global, &owned); err != nil {
		return err
	}
	if global >= s.maxGrants || owned >= s.maxOwnerGrants {
		return ErrCapacity
	}
	if person {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM meter_grants WHERE owner=? AND endpoint=?`, owner, resource).Scan(&count); err != nil {
			return err
		}
		if count >= s.maxResourcePeople {
			return ErrCapacity
		}
	}
	return nil
}

func (s *Store) sharingMutationAdmission(ctx context.Context, tx *sql.Tx, owner string) error {
	minute := s.now().Unix() / 60
	if _, err := tx.ExecContext(ctx, `DELETE FROM sharing_mutation_rate WHERE minute<?`, minute-60); err != nil {
		return err
	}
	var count int
	err := tx.QueryRowContext(ctx, `SELECT count FROM sharing_mutation_rate WHERE owner=? AND minute=?`, owner, minute).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if count >= s.maxSharingMutations {
		return ErrSharingRate
	}
	var total int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM sharing_mutation_rate WHERE owner<>?`, owner).Scan(&total); err != nil {
		return err
	}
	if total >= s.maxGrants {
		return ErrCapacity
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sharing_mutation_rate(owner,minute,count) VALUES(?,?,?) ON CONFLICT(owner) DO UPDATE SET minute=excluded.minute,count=excluded.count`, owner, minute, count+1)
	return err
}

// History is metadata only, separate from authorization and independently
// bounded per owner and globally. Eviction never alters the current decision.
func (s *Store) sharingAudit(ctx context.Context, tx *sql.Tx, owner, resource, target, action string, g *pb.Grant) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO sharing_audit(owner,resource,actor,target,action,decided_at,grant_id,expires,revoked) VALUES(?,?,?,?,?,?,?,?,?)`, owner, resource, owner, target, action, s.now().UnixMilli(), g.Id, g.ExpiresAt, g.Revoked); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sharing_audit WHERE sequence IN (SELECT sequence FROM sharing_audit WHERE owner=? ORDER BY sequence DESC LIMIT -1 OFFSET ?)`, owner, s.maxOwnerSharingAudit); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM sharing_audit WHERE sequence IN (SELECT sequence FROM sharing_audit ORDER BY sequence DESC LIMIT -1 OFFSET ?)`, s.maxSharingAudit)
	return err
}
