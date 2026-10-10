package metering

import "database/sql"

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
