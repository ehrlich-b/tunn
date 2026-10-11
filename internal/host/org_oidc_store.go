package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// Fixed partitions reserve capacity for every configured organization (at most 32).
const orgLoginGlobalLimit = 4096
const orgLoginOrgLimit = orgLoginGlobalLimit / 32
const orgLoginSourceLimit = 8

var errOrgLoginAdmission = errors.New("too many pending organization logins")

type orgLoginStore struct{ db *sql.DB }

// Use the TCP peer, never caller-controlled forwarding headers or cookies.
// Group IPv6 privacy addresses by /64. Behind a proxy this conservatively limits
// the proxy's peers together; widening trust requires an explicit proxy policy.
func orgLoginSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return orgStateDigest("unknown-peer")
	}
	addr = addr.Unmap()
	if addr.Is6() {
		return orgStateDigest(netip.PrefixFrom(addr, 64).Masked().String())
	}
	return orgStateDigest(addr.String())
}

type orgLogin struct {
	Org, Nonce, Verifier, ReturnTo, DeviceCode, Source string
	Expires                                            int64
}

func newOrgLoginStore(db *sql.DB) (*orgLoginStore, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS org_oidc_logins (
	 state TEXT PRIMARY KEY, org TEXT NOT NULL, nonce TEXT NOT NULL, verifier TEXT NOT NULL,
	 return_to TEXT NOT NULL, device_code TEXT NOT NULL, expires INTEGER NOT NULL);
	 CREATE INDEX IF NOT EXISTS org_oidc_logins_expiry ON org_oidc_logins(expires);`)
	if err != nil {
		return nil, err
	}
	var columns int
	if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info('org_oidc_logins') WHERE name='source'`).Scan(&columns); err != nil {
		return nil, err
	}
	if columns == 0 {
		// Upgrade invalidates pending pre-admission flows; completed sessions survive.
		tx, err := db.Begin()
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		if _, err = tx.Exec(`ALTER TABLE org_oidc_logins ADD COLUMN source TEXT NOT NULL DEFAULT ''; DELETE FROM org_oidc_logins;`); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS org_oidc_logins_org_source ON org_oidc_logins(org,source);`)
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
	var count, orgCount, sourceCount int
	if err = tx.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM org_oidc_logins),
  (SELECT count(*) FROM org_oidc_logins WHERE org=?),
  (SELECT count(*) FROM org_oidc_logins WHERE org=? AND source=?)`, login.Org, login.Org, login.Source).Scan(&count, &orgCount, &sourceCount); err != nil {
		return err
	}
	if count >= orgLoginGlobalLimit || orgCount >= orgLoginOrgLimit || sourceCount >= orgLoginSourceLimit {
		return errOrgLoginAdmission
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO org_oidc_logins(state,org,nonce,verifier,return_to,device_code,expires,source) VALUES(?,?,?,?,?,?,?,?)`, orgStateDigest(state), login.Org, login.Nonce, login.Verifier, login.ReturnTo, login.DeviceCode, login.Expires, login.Source)
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
