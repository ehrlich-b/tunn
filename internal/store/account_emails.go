package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
)

var ErrEmailOwned = errors.New("This email already belongs to another account.")
var ErrPrimaryEmail = errors.New("Choose another primary email before removing this one.")
var ErrEmailNotLinked = errors.New("This email is not verified on your account.")

// MutateAccountEmail changes only mailbox metadata in one authoritative transaction.
// In particular, linking must never call the provider account-merge path.
func (s *AccountStore) MutateAccountEmail(ctx context.Context, accountID, email, action string) (*Account, error) {
	email = common.NormalizeEmail(email)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var primary string
	if err = tx.QueryRowContext(ctx, "SELECT primary_email FROM accounts WHERE id=?", accountID).Scan(&primary); err != nil {
		return nil, err
	}
	var owner string
	err = tx.QueryRowContext(ctx, "SELECT account_id FROM account_emails WHERE email=?", email).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if owner != "" && owner != accountID {
		return nil, ErrEmailOwned
	}
	switch action {
	case "link":
		if owner == "" {
			_, err = tx.ExecContext(ctx, "INSERT INTO account_emails(account_id,email,verified_via,added_at) VALUES(?,?,'magic_link',?)", accountID, email, time.Now().Unix())
		}
	case "primary":
		if owner != accountID {
			return nil, ErrEmailNotLinked
		}
		_, err = tx.ExecContext(ctx, "UPDATE accounts SET primary_email=? WHERE id=?", email, accountID)
	case "remove":
		if primary == email {
			return nil, ErrPrimaryEmail
		}
		if owner != accountID {
			return nil, ErrEmailNotLinked
		}
		if err = bindCredentialOwners(ctx, tx); err != nil {
			return nil, err
		}
		// Mailbox consent issued before removal cannot enroll a key after the
		// address is reused, even if the key was not linked yet.
		for _, table := range []string{"ssh_key_links", "ssh_key_proofs"} {
			var exists int
			if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&exists); err != nil {
				return nil, err
			}
			if exists != 0 {
				if _, err = tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE email=?", email); err != nil {
					return nil, err
				}
			}
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM account_emails WHERE account_id=? AND email=?", accountID, email)
	default:
		return nil, ErrEmailNotLinked
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetByIDContext(ctx, accountID)
}
