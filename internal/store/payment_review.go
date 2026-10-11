package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func migratePaymentReview(tx *sql.Tx) error {
	var installed bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM pragma_table_info('ops_checkout_payments') WHERE name='resolution')`).Scan(&installed); err != nil {
		return err
	}
	if !installed {
		if _, err := tx.Exec(`ALTER TABLE ops_checkout_payments RENAME TO ops_checkout_payments_before_review;
 CREATE TABLE ops_checkout_payments (
 provider TEXT NOT NULL,subscription_id TEXT NOT NULL,customer_id TEXT NOT NULL,
 reference TEXT REFERENCES ops_checkout_intents(reference),outcome TEXT NOT NULL,event_id TEXT NOT NULL,
 account_id TEXT NOT NULL DEFAULT '',session_id TEXT NOT NULL DEFAULT '',completed_at INTEGER NOT NULL DEFAULT 0,
 advisory_reference TEXT NOT NULL DEFAULT '',version INTEGER NOT NULL DEFAULT 0,resolution TEXT NOT NULL DEFAULT '',approval_version INTEGER NOT NULL DEFAULT -1,approved_at INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(provider,subscription_id));
 INSERT INTO ops_checkout_payments(provider,subscription_id,customer_id,reference,outcome,event_id,account_id,advisory_reference)
 SELECT p.provider,p.subscription_id,p.customer_id,p.reference,p.outcome,p.event_id,COALESCE(i.account_id,''),p.reference FROM ops_checkout_payments_before_review p LEFT JOIN ops_checkout_intents i USING(reference);
 DROP TABLE ops_checkout_payments_before_review;
 CREATE INDEX ops_checkout_payment_reference ON ops_checkout_payments(reference);
 CREATE UNIQUE INDEX ops_checkout_session ON ops_checkout_payments(provider,session_id) WHERE session_id!='';
 `); err != nil {
			return err
		}
	}
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS ops_billing_merged_purchases(provider TEXT NOT NULL,subscription_id TEXT NOT NULL,PRIMARY KEY(provider,subscription_id));

 CREATE TABLE IF NOT EXISTS ops_payment_review_audit (
 id TEXT PRIMARY KEY,provider TEXT NOT NULL,subscription_id TEXT NOT NULL,account_id TEXT NOT NULL,
 version INTEGER NOT NULL,action TEXT NOT NULL,reason TEXT NOT NULL,actor TEXT NOT NULL,
 evidence_sha256 TEXT NOT NULL,provider_read_at TEXT NOT NULL,refund_id TEXT NOT NULL,cancellation_id TEXT NOT NULL,changed_at TEXT NOT NULL,decision_json TEXT NOT NULL DEFAULT '');
 `)
	return err
}

type PaymentReview struct {
	Provider          string    `json:"provider"`
	SubscriptionID    string    `json:"subscription_id"`
	CustomerID        string    `json:"customer_id"`
	SessionID         string    `json:"session_id"`
	EventID           string    `json:"event_id"`
	AccountID         string    `json:"account_id"`
	ExpectedVersion   int64     `json:"expected_version"`
	Action            string    `json:"action"` // approve or refunded
	Reason            string    `json:"reason"`
	EvidenceSHA256    string    `json:"evidence_sha256"`
	ProviderReadAt    time.Time `json:"provider_read_at"`
	ReassignOwnership bool      `json:"reassign_ownership"`
	AllowAdditional   bool      `json:"allow_additional"`
	RefundID          string    `json:"refund_id"`
	CancellationID    string    `json:"cancellation_id"`
}

type PaymentQueueItem struct {
	Provider       string `json:"provider"`
	SubscriptionID string `json:"subscription_id"`
	CustomerID     string `json:"customer_id"`
	SessionID      string `json:"session_id"`
	EventID        string `json:"event_id"`
	AccountID      string `json:"account_id"`
	Outcome        string `json:"outcome"`
	Version        int64  `json:"version"`
	CompletedAt    int64  `json:"completed_at"`
}

// Unbound receipts require global visibility; scoped readers only see their
// own known accounts. Pagination follows provider/subscription, never hides
// unresolved payments behind a binding requirement.
func (s *OperationsStore) PaymentReviewQueue(ctx context.Context, p AdminPrincipal, after string) ([]PaymentQueueItem, error) {
	if err := p.authorize("*"); err != nil && len(p.accounts) == 0 {
		return nil, ErrDenied
	}
	rows, err := s.db.QueryContext(ctx, `SELECT provider,subscription_id,customer_id,session_id,event_id,account_id,outcome,version,completed_at FROM ops_checkout_payments WHERE outcome!='accepted' AND resolution='' AND provider||'/'||subscription_id>? ORDER BY provider,subscription_id`, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PaymentQueueItem{}
	for rows.Next() {
		var r PaymentQueueItem
		if err = rows.Scan(&r.Provider, &r.SubscriptionID, &r.CustomerID, &r.SessionID, &r.EventID, &r.AccountID, &r.Outcome, &r.Version, &r.CompletedAt); err != nil {
			return nil, err
		}
		scope := r.AccountID
		if scope == "" {
			scope = "*"
		}
		if p.authorize(scope) != nil {
			continue
		}
		out = append(out, r)
		if len(out) == 100 {
			break
		}
	}
	return out, rows.Err()
}

func paymentAccountConflict(ctx context.Context, q operationQuery, account, provider, sub string) (bool, error) {
	var conflict bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ops_billing_mappings WHERE account_id=? AND provider=? AND subscription_id!=?) OR EXISTS(SELECT 1 FROM ops_checkout_payments WHERE account_id=? AND provider=? AND subscription_id!=? AND (outcome='accepted' OR resolution='approved')) OR EXISTS(SELECT 1 FROM ops_legacy_entitlements WHERE account_id=? AND plan='pro')`, account, provider, sub, account, provider, sub, account).Scan(&conflict)
	return conflict, err
}

// ReviewCheckoutPayment records provider verification and a scoped CAS decision.
// Approval only unlocks binding/reviewed snapshots; it never grants service.
// Refunded closes the queue only after Bryan has canceled and refunded at the
// provider. Immutable intake evidence and resolution audits remain retained.
func (s *OperationsStore) ReviewCheckoutPayment(ctx context.Context, p AdminPrincipal, d PaymentReview) error {
	if err := p.authorize(d.AccountID); err != nil {
		return err
	}
	evidence, err := hex.DecodeString(d.EvidenceSHA256)
	age := s.now().Sub(d.ProviderReadAt)
	if d.Provider != "stripe" || !boundedText(d.AccountID, 128) || !boundedText(d.Reason, 256) || len(evidence) != 32 || err != nil || age < 0 || age > 5*time.Minute || d.ProviderReadAt.IsZero() || d.ExpectedVersion < 0 || d.Action != "approve" && d.Action != "refunded" {
		return fmt.Errorf("payment review requires scoped, reasoned fresh provider evidence and a CAS decision")
	}
	if d.Action == "refunded" && (!boundedText(d.RefundID, 128) || !boundedText(d.CancellationID, 128)) {
		return fmt.Errorf("refunded requires refund and cancellation evidence IDs")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	account, err := canonicalAccount(ctx, tx, d.AccountID)
	if err != nil {
		return err
	}
	if err = p.authorize(account); err != nil {
		return err
	}
	var owner, customer, session, event, resolution, outcome string
	var version int64
	if err = tx.QueryRowContext(ctx, `SELECT account_id,customer_id,session_id,event_id,version,resolution,outcome FROM ops_checkout_payments WHERE provider=? AND subscription_id=?`, d.Provider, d.SubscriptionID).Scan(&owner, &customer, &session, &event, &version, &resolution, &outcome); err != nil {
		return err
	}
	if owner != "" {
		if err = p.authorize(owner); err != nil {
			return err
		}
		if owner != account && !d.ReassignOwnership {
			return fmt.Errorf("known payment ownership conflicts")
		}
	}
	if version != d.ExpectedVersion || resolution != "" {
		return ErrVersionConflict
	}
	if customer != d.CustomerID || session != d.SessionID || event != d.EventID || outcome == "accepted" && !(d.ReassignOwnership && owner != account) {
		return fmt.Errorf("payment evidence association conflicts")
	}
	// Even an unknown reference cannot smuggle an extra subscription into an
	// already billed account. A legitimate additional purchase needs a reasoned
	// explicit decision; duplicate refunds remain in quarantine until completion.
	conflict, err := paymentAccountConflict(ctx, tx, account, d.Provider, d.SubscriptionID)
	if err != nil {
		return err
	}
	if d.Action == "approve" && (conflict || outcome == "duplicate_payment_refund_needed") && !d.AllowAdditional {
		return fmt.Errorf("additional purchase requires explicit allow_additional review")
	}
	if d.Action == "approve" {
		var mappingConflict bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ops_billing_mappings WHERE provider=? AND (customer_id=? OR subscription_id=?) AND NOT(customer_id=? AND subscription_id=? AND account_id=?))`, d.Provider, d.CustomerID, d.SubscriptionID, d.CustomerID, d.SubscriptionID, account).Scan(&mappingConflict); err != nil {
			return err
		}
		if mappingConflict {
			return fmt.Errorf("conflicting binding requires ownership repair or cancellation/refund; approval cannot fulfill it")
		}
	}
	resolution = "approved"
	if d.Action == "refunded" {
		resolution = "refunded"
	}
	audit := uuid.NewString()
	decisionJSON, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO ops_payment_review_audit VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, audit, d.Provider, d.SubscriptionID, account, version+1, d.Action, d.Reason, p.actor, d.EvidenceSHA256, d.ProviderReadAt.UTC().Format(time.RFC3339Nano), d.RefundID, d.CancellationID, s.now().UTC().Format(time.RFC3339Nano), string(decisionJSON)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE ops_checkout_payments SET account_id=?,version=version+1,resolution=?,approval_version=COALESCE((SELECT version FROM ops_billing_mappings WHERE provider=? AND subscription_id=?),0),approved_at=? WHERE provider=? AND subscription_id=?`, account, resolution, d.Provider, d.SubscriptionID, d.ProviderReadAt.UnixNano(), d.Provider, d.SubscriptionID); err != nil {
		return err
	}
	if d.Action == "approve" {
		if _, err = tx.ExecContext(ctx, `UPDATE ops_billing_events SET account_id=?,outcome='reconciliation_required',reconciled_by=? WHERE provider=? AND event_id=?`, account, audit, d.Provider, event); err != nil {
			return err
		}
	}
	if err = projectBillingAccount(ctx, tx, account); err != nil {
		return err
	}
	return tx.Commit()
}

func billingNotice(ctx context.Context, q operationQuery, id string) (string, error) {
	var duplicate, pending bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ops_checkout_payments WHERE account_id=? AND resolution='' AND outcome='duplicate_payment_refund_needed'),EXISTS(SELECT 1 FROM ops_checkout_payments WHERE account_id=? AND resolution='' AND outcome!='accepted')`, id, id).Scan(&duplicate, &pending)
	if duplicate {
		return "duplicate_payment_refund_needed", err
	}
	if pending {
		return "payment_review_required", err
	}
	return "", err
}

// A fresh subscription on an already paid account needs an explicit additional
// purchase decision. Distinct ownership established before a verified account
// merge is retained; ordinary receipt selection cannot bypass this boundary.
func stripeAdditionalPurchaseCanGrant(ctx context.Context, q operationQuery, account, sub string) error {
	var allowed, conflict bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ops_checkout_payments WHERE provider='stripe' AND subscription_id=? AND account_id=? AND resolution='approved') OR EXISTS(SELECT 1 FROM ops_billing_states WHERE provider='stripe' AND subscription_id=? AND plan='pro') OR EXISTS(SELECT 1 FROM ops_billing_events WHERE provider='stripe' AND subscription_id=? AND event_type='snapshot.reconciled' AND plan='pro') OR EXISTS(SELECT 1 FROM ops_billing_merged_purchases WHERE provider='stripe' AND subscription_id=?), EXISTS(SELECT 1 FROM ops_billing_mappings m JOIN ops_billing_states s USING(provider,subscription_id) WHERE m.provider='stripe' AND m.account_id=? AND m.subscription_id!=? AND s.plan='pro') OR EXISTS(SELECT 1 FROM ops_checkout_payments WHERE provider='stripe' AND account_id=? AND subscription_id!=? AND (outcome='accepted' OR resolution='approved')) OR EXISTS(SELECT 1 FROM ops_legacy_entitlements WHERE account_id=? AND plan='pro')`, sub, account, sub, sub, sub, account, sub, account, sub, account).Scan(&allowed, &conflict)
	if err != nil {
		return err
	}
	if conflict && !allowed {
		return fmt.Errorf("additional subscription requires an explicit payment-review decision")
	}
	return nil
}
