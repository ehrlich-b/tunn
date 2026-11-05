package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrNameConflict = errors.New("name unavailable or not owned by this account")

// ReplaceSubdomain exchanges one owned reservation in a single transaction.
// It never edits endpoints: even offline host manifests must remain intact.
func (s *AccountStore) ReplaceSubdomain(ctx context.Context, accountID, oldName, newName string) error {
	if oldName == newName || oldName == "" || newName == "" {
		return ErrNameConflict
	}
	if err := CheckNewSharedReservation(newName); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	status, err := readAccountStatus(ctx, tx, accountID)
	if err != nil {
		return err
	}
	if status.State != "active" {
		return ErrSuspended
	}
	accountID = status.AccountID
	plan, _, err := billingAccountState(ctx, tx, accountID)
	if err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM reserved_subdomains WHERE account_id=?", accountID).Scan(&count); err != nil {
		return err
	}
	if count > ReservedSubdomainLimit(plan) {
		return fmt.Errorf("reservation allowance exceeded")
	}
	// Persistent host bindings cannot be renamed by this control, including offline ones.
	var hosts bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='host_endpoints')").Scan(&hosts); err != nil {
		return err
	}
	if hosts {
		var bound bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM host_endpoints WHERE name IN (?,?))", oldName, newName).Scan(&bound); err != nil {
			return err
		}
		if bound {
			return ErrNameConflict
		}
	}
	if err = releaseSubdomain(ctx, tx, accountID, oldName); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO reserved_subdomains(subdomain,account_id,created_at) VALUES(?,?,?)", newName, accountID, time.Now().Unix()); err != nil {
		return err
	}
	if plan == "free" {
		if _, err = tx.ExecContext(ctx, "INSERT INTO free_reservation_claims VALUES(?)", newName); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Both release paths use the same owner predicate, including merged accounts.
func releaseSubdomain(ctx context.Context, tx *sql.Tx, accountID, name string) error {
	result, err := tx.ExecContext(ctx, `DELETE FROM reserved_subdomains WHERE subdomain=? AND account_id=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?)`, name, accountID, accountID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrNameConflict
	}
	return nil
}
