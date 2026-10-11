package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

type orgLoginStore struct{ db *sql.DB }

type orgLogin struct {
	Org, Nonce, Verifier, ReturnTo, DeviceCode string
	Expires                                    int64
}

func newOrgLoginStore(db *sql.DB) (*orgLoginStore, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS org_oidc_logins (
	 state TEXT PRIMARY KEY, org TEXT NOT NULL, nonce TEXT NOT NULL, verifier TEXT NOT NULL,
	 return_to TEXT NOT NULL, device_code TEXT NOT NULL, expires INTEGER NOT NULL);
	 CREATE INDEX IF NOT EXISTS org_oidc_logins_expiry ON org_oidc_logins(expires);`)
	return &orgLoginStore{db: db}, err
}

func orgStateDigest(state string) string {
	d := sha256.Sum256([]byte(state))
	return hex.EncodeToString(d[:])
}

func (s *orgLoginStore) begin(ctx context.Context, state string, login orgLogin, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM org_oidc_logins WHERE expires<=?`, now.Unix()); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM org_oidc_logins`).Scan(&count); err != nil {
		return err
	}
	if count >= 4096 {
		return fmt.Errorf("too many pending organization logins")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO org_oidc_logins VALUES(?,?,?,?,?,?,?)`, orgStateDigest(state), login.Org, login.Nonce, login.Verifier, login.ReturnTo, login.DeviceCode, login.Expires)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Consumption is atomic and occurs before code exchange. A failed callback
// requires a new login; it cannot be retried with an already consumed state.
func (s *orgLoginStore) consume(ctx context.Context, state, org string, now time.Time) (orgLogin, error) {
	var login orgLogin
	err := s.db.QueryRowContext(ctx, `DELETE FROM org_oidc_logins WHERE state=? AND org=? AND expires>? RETURNING org,nonce,verifier,return_to,device_code,expires`, orgStateDigest(state), org, now.Unix()).Scan(&login.Org, &login.Nonce, &login.Verifier, &login.ReturnTo, &login.DeviceCode, &login.Expires)
	if err != nil {
		return orgLogin{}, fmt.Errorf("invalid, expired or consumed organization login")
	}
	return login, nil
}
