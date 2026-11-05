package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
)

// funnelDB is implemented by both a database and an existing transaction.
type funnelDB interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// RecordFunnel is best effort. The account identifier is never stored in the ledger.
func RecordFunnel(ctx context.Context, db funnelDB, stage, account string) {
	if account == "" {
		return
	}
	switch stage {
	case "signup", "tunnel", "mcp_consent", "checkout_start", "checkout_completed", "pro_active":
	default:
		return
	}
	var salt []byte
	if db.QueryRowContext(ctx, `SELECT salt FROM funnel_secret WHERE id=1`).Scan(&salt) != nil {
		return
	}
	h := hmac.New(sha256.New, salt)
	_, _ = h.Write([]byte(account))
	_, _ = db.ExecContext(ctx, `INSERT OR IGNORE INTO funnel_events(stage,account_hash,occurred_at) VALUES(?,?,?)`, stage, hex.EncodeToString(h.Sum(nil)), time.Now().UTC().Format(time.RFC3339Nano))
}

type FunnelDay struct {
	Day   string `json:"day"`
	Stage string `json:"stage"`
	Count int    `json:"count"`
}
type FunnelReport struct {
	Days               []FunnelDay `json:"days"`
	CheckoutWithoutPro int         `json:"checkout_without_pro"`
}

// FunnelReport is an aggregate across accounts and therefore requires global access.
func (s *OperationsStore) FunnelReport(ctx context.Context, principal AdminPrincipal) (*FunnelReport, error) {
	if err := principal.authorize("*"); err != nil {
		return nil, err
	}
	out := &FunnelReport{Days: []FunnelDay{}}
	rows, err := s.db.QueryContext(ctx, `SELECT substr(occurred_at,1,10),stage,count(*) FROM funnel_events GROUP BY 1,2 ORDER BY 1,2`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d FunnelDay
		if err = rows.Scan(&d.Day, &d.Stage, &d.Count); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out.Days = append(out.Days, d)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	lower, upper := now.Add(-24*time.Hour).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)
	err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM funnel_events c WHERE c.stage='checkout_completed' AND c.occurred_at >= ? AND c.occurred_at <= ? AND NOT EXISTS (SELECT 1 FROM funnel_events p WHERE p.stage='pro_active' AND p.account_hash=c.account_hash AND p.occurred_at >= ? AND p.occurred_at <= ?)`, lower, upper, lower, upper).Scan(&out.CheckoutWithoutPro)
	return out, err
}
