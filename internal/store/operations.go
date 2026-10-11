package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrSuspended = errors.New("account suspended")
var ErrVersionConflict = errors.New("account version conflict")
var ErrDenied = errors.New("administration denied")

// OperationsSchema uses isolated tables so domain/quota migrations can coexist.
// Verified billing state and preserved legacy grants project account plans.
const OperationsSchema = `
CREATE TABLE IF NOT EXISTS ops_account_state (
 account_id TEXT PRIMARY KEY REFERENCES accounts(id),
 state TEXT NOT NULL CHECK(state IN ('active','suspended')),
 version INTEGER NOT NULL CHECK(version > 0),
 reason TEXT NOT NULL, actor TEXT NOT NULL, changed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ops_account_audit (
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL, original_account_id TEXT NOT NULL, version INTEGER NOT NULL,
 previous_state TEXT NOT NULL, state TEXT NOT NULL,
 reason TEXT NOT NULL, actor TEXT NOT NULL, changed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ops_audit_account ON ops_account_audit(account_id,version);
CREATE TABLE IF NOT EXISTS ops_billing_mappings (
 provider TEXT NOT NULL, subscription_id TEXT NOT NULL, customer_id TEXT NOT NULL,
 account_id TEXT NOT NULL REFERENCES accounts(id), version INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 0, plan TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(provider,subscription_id), UNIQUE(provider,customer_id)
);
CREATE INDEX IF NOT EXISTS ops_billing_account ON ops_billing_mappings(account_id);
CREATE TABLE IF NOT EXISTS ops_billing_states (
 provider TEXT NOT NULL, subscription_id TEXT NOT NULL,
 plan TEXT NOT NULL CHECK(plan IN ('free','pro')), revision INTEGER NOT NULL,
 provider_read_at INTEGER NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(provider,subscription_id),
 FOREIGN KEY(provider,subscription_id) REFERENCES ops_billing_mappings(provider,subscription_id),
 CHECK(revision > 0 OR provider_read_at > 0)
);
CREATE TABLE IF NOT EXISTS ops_checkout_intents (
 reference TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ops_checkout_account ON ops_checkout_intents(account_id);
CREATE TABLE IF NOT EXISTS ops_checkout_destinations (
 reference TEXT PRIMARY KEY REFERENCES ops_checkout_intents(reference),
 destination TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ops_checkout_payments (
 provider TEXT NOT NULL, subscription_id TEXT NOT NULL, customer_id TEXT NOT NULL,
 reference TEXT NOT NULL REFERENCES ops_checkout_intents(reference),
 outcome TEXT NOT NULL, event_id TEXT NOT NULL,
 PRIMARY KEY(provider,subscription_id)
);
CREATE INDEX IF NOT EXISTS ops_checkout_payment_reference ON ops_checkout_payments(reference);
CREATE TABLE IF NOT EXISTS ops_legacy_entitlements (
 original_account_id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 plan TEXT NOT NULL CHECK(plan IN ('pro','free')), version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ops_legacy_account ON ops_legacy_entitlements(account_id);
CREATE TABLE IF NOT EXISTS ops_legacy_entitlement_audit (
 id TEXT PRIMARY KEY, original_account_id TEXT NOT NULL, account_id TEXT NOT NULL,
 previous_plan TEXT NOT NULL, plan TEXT NOT NULL, version INTEGER NOT NULL,
 reason TEXT NOT NULL, actor TEXT NOT NULL, changed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ops_billing_events (
 provider TEXT NOT NULL, event_id TEXT NOT NULL, digest TEXT NOT NULL,
 event_type TEXT NOT NULL, subscription_id TEXT NOT NULL, customer_id TEXT NOT NULL,
 account_id TEXT NOT NULL, revision INTEGER NOT NULL, plan TEXT NOT NULL,
 outcome TEXT NOT NULL, received_at TEXT NOT NULL, actor TEXT NOT NULL DEFAULT '', reconciled_by TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(provider,event_id)
);
CREATE TABLE IF NOT EXISTS ops_reports (
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL, category TEXT NOT NULL,
 endpoint TEXT NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL,
 created_at TEXT NOT NULL, changed_at TEXT NOT NULL, actor TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ops_reports_account ON ops_reports(account_id);
`

type AccountStatus struct {
	AccountID string `json:"account_id"`
	State     string `json:"state"`
	Version   int64  `json:"version"`
	Reason    string `json:"reason"`
	Actor     string `json:"actor"`
	ChangedAt string `json:"changed_at"`
}

// AdminCredential is operator-owned configuration, analogous to users.yaml.
// Credentials are independent of publisher, visitor, grant, and payment tokens.
type AdminCredential struct {
	Actor       string   `json:"actor"`
	TokenSHA256 string   `json:"token_sha256"`
	Accounts    []string `json:"accounts"`
}
type AdminPrincipal struct {
	actor    string
	accounts []string
}

func AuthenticateAdmin(credentials []AdminCredential, token string) (AdminPrincipal, error) {
	if len(token) < 32 || len(token) > 512 {
		return AdminPrincipal{}, ErrDenied
	}
	digest := sha256.Sum256([]byte(token))
	for _, c := range credentials {
		want, err := hex.DecodeString(c.TokenSHA256)
		if err == nil && len(want) == len(digest) && subtle.ConstantTimeCompare(want, digest[:]) == 1 && boundedText(c.Actor, 128) && len(c.Accounts) > 0 {
			return AdminPrincipal{c.Actor, append([]string(nil), c.Accounts...)}, nil
		}
	}
	return AdminPrincipal{}, ErrDenied
}
func (p AdminPrincipal) authorize(account string) error {
	if p.actor == "" {
		return ErrDenied
	}
	for _, a := range p.accounts {
		if a == "*" || a == account {
			return nil
		}
	}
	return ErrDenied
}
func boundedText(s string, max int) bool {
	return strings.TrimSpace(s) != "" && len(s) <= max && !strings.ContainsAny(s, "\x00\r\n")
}

type OperationsStore struct {
	db  *sql.DB
	now func() time.Time
}

func NewOperationsStore(db *sql.DB, now func() time.Time) *OperationsStore {
	if now == nil {
		now = time.Now
	}
	return &OperationsStore{db, now}
}
func MigrateOperations(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var installed bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='ops_legacy_entitlements')`).Scan(&installed); err != nil {
		return err
	}
	if _, err = tx.Exec(OperationsSchema); err != nil {
		return err
	}
	// Install schema without changing any plan or reservation. Snapshot legacy
	// grants exactly once, before the new reducer reads accounts. Existing verified
	// projections are not legacy grants. Only an audited global operator action
	// may end these preserved entitlements; restarts never re-import revoked ones.
	if !installed {
		if _, err = tx.Exec(`INSERT INTO ops_legacy_entitlements(original_account_id,account_id,plan)
 SELECT id,id,'pro' FROM accounts WHERE plan='pro' AND NOT EXISTS(
 SELECT 1 FROM ops_billing_mappings m JOIN ops_billing_states s USING(provider,subscription_id)
 WHERE m.account_id=accounts.id)`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type operationQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func canonicalAccount(ctx context.Context, q operationQuery, id string) (string, error) {
	var out string
	err := q.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?)`, id, id).Scan(&out)
	return out, err
}
func readAccountStatus(ctx context.Context, q operationQuery, id string) (*AccountStatus, error) {
	id, err := canonicalAccount(ctx, q, id)
	if err != nil {
		return nil, err
	}
	out := &AccountStatus{AccountID: id, State: "active"}
	err = q.QueryRowContext(ctx, `SELECT state,version,reason,actor,changed_at FROM ops_account_state WHERE account_id=?`, id).Scan(&out.State, &out.Version, &out.Reason, &out.Actor, &out.ChangedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return out, err
}
func (s *OperationsStore) LookupAccountStatus(ctx context.Context, id string) (*AccountStatus, error) {
	return readAccountStatus(ctx, s.db, id)
}
func (s *OperationsStore) AdminStatus(ctx context.Context, p AdminPrincipal, id string) (*AccountStatus, error) {
	if err := p.authorize(id); err != nil {
		return nil, err
	}
	state, err := s.LookupAccountStatus(ctx, id)
	if err != nil {
		return nil, err
	}
	if err = p.authorize(state.AccountID); err != nil {
		return nil, err
	}
	return state, nil
}
func (s *OperationsStore) AdminMigrate(ctx context.Context, p AdminPrincipal, id string) error {
	if err := p.authorize(id); err != nil {
		return err
	}
	canonical, err := canonicalAccount(ctx, s.db, id)
	if err != nil {
		return err
	}
	if err = p.authorize(canonical); err != nil {
		return err
	}
	return MigrateOperations(s.db)
}

// Transition is compare-and-swap. Resume is suspended -> active and increments
// the same durable version; it cannot accidentally undo a newer suspension.
func (s *OperationsStore) Transition(ctx context.Context, p AdminPrincipal, id, state, reason string, expected int64) (*AccountStatus, error) {
	if err := p.authorize(id); err != nil {
		return nil, err
	}
	if (state != "active" && state != "suspended") || !boundedText(reason, 256) || expected < 0 {
		return nil, fmt.Errorf("invalid account transition")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	old, err := readAccountStatus(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err = p.authorize(old.AccountID); err != nil {
		return nil, err
	}
	if old.Version != expected {
		return nil, ErrVersionConflict
	}
	if old.State == state {
		return nil, fmt.Errorf("account already %s", state)
	}
	out := &AccountStatus{old.AccountID, state, old.Version + 1, reason, p.actor, s.now().UTC().Format(time.RFC3339Nano)}
	if err = writeAccountStatus(ctx, tx, old, out); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
func writeAccountStatus(ctx context.Context, tx *sql.Tx, old, out *AccountStatus) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO ops_account_state(account_id,state,version,reason,actor,changed_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(account_id) DO UPDATE SET state=excluded.state,version=excluded.version,reason=excluded.reason,actor=excluded.actor,changed_at=excluded.changed_at`, out.AccountID, out.State, out.Version, out.Reason, out.Actor, out.ChangedAt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ops_account_audit(id,account_id,original_account_id,version,previous_state,state,reason,actor,changed_at) VALUES(?,?,?,?,?,?,?,?,?)`, uuid.NewString(), out.AccountID, out.AccountID, out.Version, old.State, out.State, out.Reason, out.Actor, out.ChangedAt)
	return err
}

func mergeAccountOperations(tx *sql.Tx, from, to string) error {
	ctx := context.Background()
	a, err := readAccountStatus(ctx, tx, from)
	if err != nil {
		return err
	}
	b, err := readAccountStatus(ctx, tx, to)
	if err != nil {
		return err
	}
	if a.Version > 0 || b.Version > 0 {
		state := "active"
		if a.State == "suspended" || b.State == "suspended" {
			state = "suspended"
		}
		out := &AccountStatus{to, state, max(a.Version, b.Version) + 1, "verified account merge; prior controls retained", "system:account-merge", time.Now().UTC().Format(time.RFC3339Nano)}
		if err = writeAccountStatus(ctx, tx, b, out); err != nil {
			return err
		}
	}
	for _, table := range []string{"ops_account_audit", "ops_billing_mappings", "ops_billing_events", "ops_checkout_intents", "ops_legacy_entitlements", "ops_reports"} {
		if _, err = tx.Exec("UPDATE "+table+" SET account_id=? WHERE account_id=?", to, from); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("DELETE FROM ops_account_state WHERE account_id=?", from); err != nil {
		return err
	}
	return projectBillingAccount(ctx, tx, to)
}
