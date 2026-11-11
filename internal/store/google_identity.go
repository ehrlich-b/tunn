package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ehrlich-b/tunn/internal/common"
)

// FindOrCreateGoogleIdentity never treats a historical third-party verification
// as mailbox proof. Unbound identities require Google's authoritative email;
// changing a bound identity's email requires a separate mailbox/linking flow.
func (s *AccountStore) FindOrCreateGoogleIdentity(ctx context.Context, subject, email, hostedDomain string, verified bool) (*Account, error) {
	if subject == "" || len(subject) > 255 || !common.GoogleAuthoritativeEmail(email, hostedDomain, verified) {
		return nil, fmt.Errorf("authoritative verified Google identity required")
	}
	email = strings.ToLower(email)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var accountID, boundEmail string
	err = tx.QueryRowContext(ctx, `SELECT account_id,email FROM account_provider_identities WHERE issuer=? AND subject=?`, common.GoogleIssuer, subject).Scan(&accountID, &boundEmail)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil && boundEmail != email {
		return nil, fmt.Errorf("Google email changed; fresh mailbox linking required")
	}
	// A known subject must still own its bound mailbox; never resolve it to a
	// different account just because the provider supplied another email.
	if accountID != "" {
		var owner string
		if err = tx.QueryRowContext(ctx, `SELECT account_id FROM account_emails WHERE email=?`, email).Scan(&owner); err != nil {
			return nil, err
		}
		if owner != accountID {
			return nil, fmt.Errorf("Google subject account mismatch")
		}
	}
	account, err := s.findOrCreateByEmailsTx(ctx, tx, []string{email}, "google")
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO account_provider_identities(issuer,subject,account_id,email) VALUES(?,?,?,?) ON CONFLICT(issuer,subject) DO NOTHING`, common.GoogleIssuer, subject, account.ID, email); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return account, nil
}
