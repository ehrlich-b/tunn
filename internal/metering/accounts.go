package metering

import (
	"database/sql"
	"errors"
)

func operationallySuspended(tx *sql.Tx, owner string) (bool, error) {
	var exists int
	if err := tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='ops_account_state'").Scan(&exists); err != nil {
		return false, err
	}
	if exists == 0 {
		return false, nil
	}
	var state string
	err := tx.QueryRow("SELECT state FROM ops_account_state WHERE account_id=?", owner).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return state != "active", err
}

// canonicalOwner handles admission/grant creation that raced an account merge.
// Standalone ledgers have no account schema and retain their supplied owners.
func canonicalOwner(tx *sql.Tx, owner string) (string, error) {
	var exists int
	if err := tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='account_merges'").Scan(&exists); err != nil {
		return "", err
	}
	if exists == 0 {
		return owner, nil
	}
	var canonical string
	err := tx.QueryRow("SELECT COALESCE((SELECT account_id FROM account_merges WHERE old_id=?), ?)", owner, owner).Scan(&canonical)
	return canonical, err
}
