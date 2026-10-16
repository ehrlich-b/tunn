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
		{"device_codes", "email"}, {"durable_devices", "email"},
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
		if credential.table == "durable_devices" || credential.table == "device_codes" {
			unbound = "unbound-credential"
		}
		for _, email := range emails {
			_, err := tx.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET account_id=COALESCE((SELECT account_id FROM account_emails WHERE email=?),?) WHERE %s=? AND account_id=''`, credential.table, credential.email), common.NormalizeEmail(email), unbound, email)
			if err != nil {
				return err
			}
		}
	}
	return bindSSHKeyOwners(ctx, tx)
}

// Keep ssh_keys in its three-column shape for rollback builds which insert
// without a column list. Triggers also bind keys enrolled by those builds.
func bindSSHKeyOwners(ctx context.Context, tx *sql.Tx) error {
	var exists, oldColumn int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='ssh_keys'").Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ssh_key_owners(fingerprint TEXT PRIMARY KEY, account_id TEXT NOT NULL)`); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM pragma_table_info('ssh_keys') WHERE name='account_id'").Scan(&oldColumn); err != nil {
		return err
	}
	if oldColumn != 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ssh_key_owners SELECT fingerprint,account_id FROM ssh_keys WHERE account_id<>'' ON CONFLICT(fingerprint) DO NOTHING`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE ssh_keys DROP COLUMN account_id"); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO ssh_key_owners(fingerprint,account_id)
 SELECT fingerprint, COALESCE((SELECT account_id FROM account_emails WHERE email=lower(trim(owner_email))),'unbound-credential') FROM ssh_keys WHERE true
 ON CONFLICT(fingerprint) DO NOTHING;
 CREATE TRIGGER IF NOT EXISTS ssh_key_owner_insert AFTER INSERT ON ssh_keys BEGIN
 INSERT INTO ssh_key_owners(fingerprint,account_id) VALUES(NEW.fingerprint,COALESCE((SELECT account_id FROM account_emails WHERE email=lower(trim(NEW.owner_email))),'unbound-credential'));
 END;
 CREATE TRIGGER IF NOT EXISTS ssh_key_owner_delete AFTER DELETE ON ssh_keys BEGIN
 DELETE FROM ssh_key_owners WHERE fingerprint=OLD.fingerprint;
 END;`)
	return err
}
