package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ehrlich-b/tunn/internal/common"
)

// MigrateCredentialOwnership binds legacy credentials while their verified
// mailboxes belong to the account. Verified mailboxes remain linked permanently.
func MigrateCredentialOwnership(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := bindCredentialOwners(context.Background(), tx); err != nil {
		return err
	}
	return tx.Commit()
}

func bindCredentialOwners(ctx context.Context, tx *sql.Tx) error {
	for _, credential := range []struct{ table, email string }{
		{"device_codes", "email"}, {"durable_devices", "email"}, {"ssh_keys", "owner_email"},
		{"ssh_key_links", "email"}, {"ssh_key_proofs", "email"},
	} {
		var exists, bound int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", credential.table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM pragma_table_info(?) WHERE name='account_id'", credential.table).Scan(&bound); err != nil {
			return err
		}
		if bound == 0 {
			if _, err := tx.ExecContext(ctx, "ALTER TABLE "+credential.table+" ADD COLUMN account_id TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		rows, err := tx.QueryContext(ctx, "SELECT DISTINCT "+credential.email+" FROM "+credential.table+" WHERE account_id='' AND "+credential.email+" IS NOT NULL AND "+credential.email+"<>''")
		if err != nil {
			return err
		}
		var emails []string
		for rows.Next() {
			var email string
			if err := rows.Scan(&email); err != nil {
				rows.Close()
				return err
			}
			emails = append(emails, email)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		unbound := ""
		if credential.table == "ssh_keys" || credential.table == "durable_devices" || credential.table == "device_codes" {
			unbound = "unbound-credential"
		}
		for _, email := range emails {
			_, err := tx.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET account_id=COALESCE((SELECT account_id FROM account_emails WHERE email=?),?) WHERE %s=? AND account_id=''`, credential.table, credential.email), common.NormalizeEmail(email), unbound, email)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
