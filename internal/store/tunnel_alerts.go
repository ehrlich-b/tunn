package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const TunnelHeartbeatLease = 90 * time.Second

type TunnelAlertSettings struct {
	Enabled          bool
	ThresholdSeconds int64
	OnGracefulStop   bool
}

type TunnelAlert struct {
	Tunnel, Owner, Email, LastError string
	Since                           time.Time
	Recovery                        bool
	Attempt                         int64
}

type TunnelAlertStore struct{ db *sql.DB }

func NewTunnelAlertStore(db *sql.DB) *TunnelAlertStore { return &TunnelAlertStore{db: db} }

func MigrateTunnelAlerts(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS tunnel_alert_settings (
 account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 enabled INTEGER NOT NULL DEFAULT 0,
 threshold_seconds INTEGER NOT NULL DEFAULT 600 CHECK(threshold_seconds BETWEEN 1 AND 604800),
 on_graceful_stop INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tunnel_availability (
 tunnel TEXT PRIMARY KEY REFERENCES reserved_subdomains(subdomain) ON DELETE CASCADE,
 owner TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 session TEXT NOT NULL,
 online INTEGER NOT NULL,
 seen_at INTEGER NOT NULL,
 offline_since INTEGER NOT NULL DEFAULT 0,
 graceful INTEGER NOT NULL DEFAULT 0,
 last_error TEXT NOT NULL DEFAULT '',
 down_sent INTEGER NOT NULL DEFAULT 0,
 last_email INTEGER NOT NULL DEFAULT 0
);`)
	if err != nil {
		return err
	}
	return migrateTunnelAlertDefault(db)
}

// SQLite's default-only schema migration leaves every saved preference and
// table row intact. Bump the schema version so other connections reparse it.
func migrateTunnelAlertDefault(db *sql.DB) error {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer conn.ExecContext(ctx, "PRAGMA writable_schema=OFF")
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var schema string
	if err = tx.QueryRow(`SELECT sql FROM sqlite_schema WHERE type='table' AND name='tunnel_alert_settings'`).Scan(&schema); err != nil {
		return err
	}
	const oldDefault = "enabled INTEGER NOT NULL DEFAULT 1"
	if !strings.Contains(schema, oldDefault) {
		return nil
	}
	var version int
	if err = tx.QueryRow("PRAGMA schema_version").Scan(&version); err != nil {
		return err
	}
	if _, err = tx.Exec("PRAGMA writable_schema=ON"); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE sqlite_schema SET sql=? WHERE type='table' AND name='tunnel_alert_settings'`, strings.Replace(schema, oldDefault, "enabled INTEGER NOT NULL DEFAULT 0", 1)); err != nil {
		return err
	}
	if _, err = tx.Exec(fmt.Sprintf("PRAGMA schema_version=%d", version+1)); err != nil {
		return err
	}
	if _, err = tx.Exec("PRAGMA writable_schema=OFF"); err != nil {
		return err
	}
	return tx.Commit()
}

// mergeTunnelAlerts keeps outage generations, delivery state and hourly budgets
// intact. Conflicting explicit preferences favor fewer notifications: opt-out,
// the longer threshold, and clean-stop alerts only when both accounts opted in.
func mergeTunnelAlerts(tx *sql.Tx, oldID, owner string) error {
	var exists int
	if err := tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='tunnel_availability'").Scan(&exists); err != nil || exists == 0 {
		return err
	}
	if _, err := tx.Exec("UPDATE tunnel_availability SET owner=? WHERE owner=?", owner, oldID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO tunnel_alert_settings(account_id,enabled,threshold_seconds,on_graceful_stop)
 SELECT ?,enabled,threshold_seconds,on_graceful_stop FROM tunnel_alert_settings WHERE account_id=?
 ON CONFLICT(account_id) DO UPDATE SET enabled=MIN(tunnel_alert_settings.enabled,excluded.enabled),
 threshold_seconds=MAX(tunnel_alert_settings.threshold_seconds,excluded.threshold_seconds),
 on_graceful_stop=MIN(tunnel_alert_settings.on_graceful_stop,excluded.on_graceful_stop)`, owner, oldID); err != nil {
		return err
	}
	_, err := tx.Exec("DELETE FROM tunnel_alert_settings WHERE account_id=?", oldID)
	return err
}

func (s *TunnelAlertStore) Settings(ctx context.Context, owner string, update *TunnelAlertSettings) (TunnelAlertSettings, error) {
	a, err := NewAccountStore(s.db).GetByIDContext(ctx, owner)
	if err != nil {
		return TunnelAlertSettings{}, err
	}
	if update != nil {
		if update.ThresholdSeconds < 1 || update.ThresholdSeconds > 604800 {
			return TunnelAlertSettings{}, fmt.Errorf("threshold must be between 1 and 604800 seconds")
		}
		_, err = s.db.ExecContext(ctx, `INSERT INTO tunnel_alert_settings VALUES(?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET enabled=excluded.enabled, threshold_seconds=excluded.threshold_seconds, on_graceful_stop=excluded.on_graceful_stop`, a.ID, update.Enabled, update.ThresholdSeconds, update.OnGracefulStop)
		if err != nil {
			return TunnelAlertSettings{}, err
		}
	}
	out := TunnelAlertSettings{ThresholdSeconds: 600}
	err = s.db.QueryRowContext(ctx, `SELECT enabled,threshold_seconds,on_graceful_stop FROM tunnel_alert_settings WHERE account_id=?`, a.ID).Scan(&out.Enabled, &out.ThresholdSeconds, &out.OnGracefulStop)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return out, err
}

// Report only creates records for a successfully published, owner-reserved name.
// A connection generation fences late disconnects and heartbeats from old nodes.
func (s *TunnelAlertStore) Report(ctx context.Context, owner, tunnel, session, operation, lastError string, now time.Time) error {
	if len(lastError) > 512 || len(session) > 128 || len(tunnel) > 63 {
		return fmt.Errorf("invalid availability report")
	}
	// Resolve obsolete publisher UUIDs in the write itself so a concurrent
	// account merge cannot strand a disconnect under the absorbed owner.
	t := now.Unix()
	switch operation {
	case "up":
		if session == "" {
			return fmt.Errorf("missing publisher generation")
		}
		_, err := s.db.ExecContext(ctx, `INSERT INTO tunnel_availability(tunnel,owner,session,online,seen_at)
 SELECT subdomain,account_id,?,1,? FROM reserved_subdomains WHERE subdomain=? AND account_id=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?)
 ON CONFLICT(tunnel) DO UPDATE SET session=excluded.session,online=1,seen_at=excluded.seen_at,graceful=0,
	 owner=excluded.owner,down_sent=CASE WHEN owner=excluded.owner THEN down_sent ELSE 0 END,
 offline_since=CASE WHEN owner=excluded.owner THEN offline_since ELSE 0 END`, session, t, tunnel, owner, owner)
		return err
	case "heartbeat":
		_, err := s.db.ExecContext(ctx, `UPDATE tunnel_availability SET online=1,seen_at=?,graceful=0 WHERE tunnel=? AND owner=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?) AND session=?`, t, tunnel, owner, owner, session)
		return err
	case "down", "graceful":
		_, err := s.db.ExecContext(ctx, `UPDATE tunnel_availability SET online=0,offline_since=CASE WHEN online=1 THEN ? ELSE offline_since END,graceful=?,last_error=? WHERE tunnel=? AND owner=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?) AND session=?`, t, operation == "graceful", lastError, tunnel, owner, owner, session)
		return err
	case "error":
		// An expired but correctly signed owner token can explain a reconnect failure.
		_, err := s.db.ExecContext(ctx, `UPDATE tunnel_availability SET last_error=? WHERE tunnel=? AND owner=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?) AND online=0`, lastError, tunnel, owner, owner)
		return err
	default:
		return fmt.Errorf("unknown availability operation")
	}
}

func (s *TunnelAlertStore) Session(ctx context.Context, tunnel string) (string, error) {
	var session string
	err := s.db.QueryRowContext(ctx, `SELECT session FROM tunnel_availability WHERE tunnel=?`, tunnel).Scan(&session)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return session, err
}

// Claim reserves an hourly mail slot durably before SMTP. A failed attempt keeps
// its rate-limit slot; only Delivered advances notification state. A crash before
// completion therefore allows a later retry while the notification still applies.
// Only the login node runs delivery; claims also fence concurrent sweeps/restarts.
func (s *TunnelAlertStore) Claim(ctx context.Context, now time.Time) ([]TunnelAlert, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	t := now.Unix()
	rows, err := tx.QueryContext(ctx, `SELECT v.tunnel,v.owner,a.primary_email,v.last_error,v.offline_since,v.online
 FROM tunnel_availability v JOIN reserved_subdomains r ON r.subdomain=v.tunnel AND r.account_id=v.owner
 JOIN accounts a ON a.id=v.owner LEFT JOIN tunnel_alert_settings p ON p.account_id=v.owner
 WHERE coalesce(p.enabled,0)=1 AND (v.last_email=0 OR v.last_email+3600<=?)
 AND ((v.online=0 AND v.down_sent=0 AND v.offline_since+coalesce(p.threshold_seconds,600)<=? AND (v.graceful=0 OR coalesce(p.on_graceful_stop,0)=1)) OR (v.online=1 AND v.down_sent=1))`, t, t)
	if err != nil {
		return nil, err
	}
	var alerts []TunnelAlert
	for rows.Next() {
		var a TunnelAlert
		var since int64
		if err = rows.Scan(&a.Tunnel, &a.Owner, &a.Email, &a.LastError, &since, &a.Recovery); err != nil {
			break
		}
		a.Since = time.Unix(since, 0)
		a.Attempt = t
		alerts = append(alerts, a)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, a := range alerts {
		if _, err = tx.ExecContext(ctx, `UPDATE tunnel_availability SET last_email=? WHERE tunnel=?`, t, a.Tunnel); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return alerts, nil
}

// Expire also returns names whose in-memory admission must be released after
// a relay crash. The local storage authority serializes this with registration.
func (s *TunnelAlertStore) Expire(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `UPDATE tunnel_availability SET online=0,offline_since=seen_at+?,graceful=0,last_error='Relay heartbeat lost' WHERE online=1 AND seen_at+?<=? RETURNING tunnel`, int64(TunnelHeartbeatLease/time.Second), int64(TunnelHeartbeatLease/time.Second), now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func (s *TunnelAlertStore) Delivered(ctx context.Context, a TunnelAlert) error {
	_, err := s.db.ExecContext(ctx, `UPDATE tunnel_availability SET down_sent=? WHERE tunnel=? AND owner=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?) AND last_email=?`, !a.Recovery, a.Tunnel, a.Owner, a.Owner, a.Attempt)
	return err
}
