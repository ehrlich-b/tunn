package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
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
	hash := funnelAccountHash(ctx, db, account)
	if hash == "" {
		return
	}
	_, _ = db.ExecContext(ctx, `INSERT OR IGNORE INTO funnel_events(stage,account_hash,occurred_at,source) VALUES(?,?,?,?)`, stage, hash, time.Now().UTC().Format(time.RFC3339Nano), common.FunnelSource(ctx))
}

func funnelAccountHash(ctx context.Context, db funnelDB, account string) string {
	var salt []byte
	if db.QueryRowContext(ctx, `SELECT salt FROM funnel_secret WHERE id=1`).Scan(&salt) != nil {
		return ""
	}
	h := hmac.New(sha256.New, salt)
	_, _ = h.Write([]byte(account))
	return hex.EncodeToString(h.Sum(nil))
}

func unboundCheckoutIdentity(provider, subscription string) string {
	return "unbound-checkout:" + provider + ":" + subscription
}

// Reconcile best effort inside the ownership transaction, preserving the first
// checkout time and one event per account. Never discard the unbound event if
// copying it fails, and never create a new event just because ownership changed.
func reconcileCheckoutFunnel(ctx context.Context, db funnelDB, provider, subscription, account string) {
	moveFunnelIdentity(ctx, db, unboundCheckoutIdentity(provider, subscription), account, true)
}

// Move only after a successful copy, so a failed best-effort write cannot
// discard the original events. Reassignment moves checkout only; a verified
// account merge consolidates every stage.
func moveFunnelIdentity(ctx context.Context, db funnelDB, oldAccount, newAccount string, checkoutOnly bool) {
	copyFunnelIdentity(ctx, db, oldAccount, newAccount, checkoutOnly, false)
}

// Retain the original account marker when another checkout still belongs to it.
func copyFunnelIdentity(ctx context.Context, db funnelDB, oldAccount, newAccount string, checkoutOnly, retainOriginal bool) {
	if oldAccount == "" || newAccount == "" {
		return
	}
	oldHash := funnelAccountHash(ctx, db, oldAccount)
	newHash := funnelAccountHash(ctx, db, newAccount)
	if oldHash == "" || newHash == "" || oldHash == newHash {
		return
	}
	filter := ""
	if checkoutOnly {
		filter = " AND stage='checkout_completed'"
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO funnel_events(stage,account_hash,occurred_at,source) SELECT stage,?,occurred_at,source FROM funnel_events WHERE account_hash=?`+filter+` ON CONFLICT(stage,account_hash) DO UPDATE SET occurred_at=min(funnel_events.occurred_at,excluded.occurred_at)`, newHash, oldHash); err != nil {
		return
	}
	if !retainOriginal {
		_, _ = db.ExecContext(ctx, `DELETE FROM funnel_events WHERE account_hash=?`+filter, oldHash)
	}
}

type FunnelDay struct {
	Day   string `json:"day"`
	Stage string `json:"stage"`
	Count int    `json:"count"`
}
type FunnelSourceDay struct {
	Day    string `json:"day"`
	Source string `json:"source"`
	Count  int    `json:"count"`
}

type FunnelReport struct {
	SignupSources      []FunnelSourceDay `json:"signup_sources"`
	Days               []FunnelDay       `json:"days"`
	CheckoutWithoutPro int               `json:"checkout_without_pro"`
}

// FunnelReport is an aggregate across accounts and therefore requires global access.
func (s *OperationsStore) FunnelReport(ctx context.Context, principal AdminPrincipal) (*FunnelReport, error) {
	if err := principal.authorize("*"); err != nil {
		return nil, err
	}
	out := &FunnelReport{Days: []FunnelDay{}, SignupSources: []FunnelSourceDay{}}
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
	rows, err = s.db.QueryContext(ctx, `SELECT substr(occurred_at,1,10),source,count(*) FROM funnel_events WHERE stage='signup' GROUP BY 1,2 ORDER BY 1,2`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d FunnelSourceDay
		if err = rows.Scan(&d.Day, &d.Source, &d.Count); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out.SignupSources = append(out.SignupSources, d)
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

// migrateFunnelSource is additive and leaves existing events intact. Historical
// events have no known channel and are grouped as other.
func migrateFunnelSource(db *sql.DB) error {
	var installed bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pragma_table_info('funnel_events') WHERE name='source')`).Scan(&installed); err != nil {
		return err
	}
	if installed {
		return nil
	}
	_, err := db.Exec(`ALTER TABLE funnel_events ADD COLUMN source TEXT NOT NULL DEFAULT 'other' CHECK(source IN ('alt','saashub','docs','thread','direct','other'))`)
	return err
}
