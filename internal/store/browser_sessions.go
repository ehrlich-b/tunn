package store

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// MigrateBrowserSessions is additive and keeps the legacy accounts row shape.
func MigrateBrowserSessions(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS browser_session_epochs (
 account_id TEXT PRIMARY KEY, epoch TEXT NOT NULL)`)
	return err
}

// RevokeBrowserSessions rotates only the epoch authenticated by the caller.
// Replaying a logout cannot revoke a later login. The single statement also
// resolves obsolete UUIDs in the same snapshot as the conditional update.
func (s *AccountStore) RevokeBrowserSessions(ctx context.Context, id, expected string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO browser_session_epochs(account_id,epoch)
 SELECT id,? FROM accounts
 WHERE id=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?)
 AND COALESCE((SELECT epoch FROM browser_session_epochs WHERE account_id=accounts.id),'')=?
 ON CONFLICT(account_id) DO UPDATE SET epoch=excluded.epoch`, uuid.NewString(), id, id, expected)
	return err
}

// Never let a previously revoked cookie become valid when UUIDs are merged.
// Unrevoked legacy accounts retain their existing sessions across a merge.
func mergeBrowserSessions(tx *sql.Tx, from, to string) error {
	_, err := tx.Exec(`INSERT INTO browser_session_epochs(account_id,epoch)
 SELECT ?,? WHERE EXISTS(SELECT 1 FROM browser_session_epochs WHERE account_id IN(?,?))
 ON CONFLICT(account_id) DO UPDATE SET epoch=excluded.epoch`, to, uuid.NewString(), from, to)
	if err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM browser_session_epochs WHERE account_id=?", from)
	return err
}
