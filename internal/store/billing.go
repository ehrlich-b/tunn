package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BillingEvent contains provider-normalized metadata, never a webhook body.
// Revision is used only by adapters with an authoritative monotonic revision.
// Stripe timestamps and event IDs do not meet that contract (Revision=0).
type BillingEvent struct {
	Provider          string `json:"provider"`
	ID                string `json:"id"`
	Type              string `json:"type"`
	CustomerID        string `json:"customer_id"`
	SubscriptionID    string `json:"subscription_id"`
	Revision          int64  `json:"revision"`
	Plan              string `json:"plan"`
	Supported         bool   `json:"supported"`
	PayloadSHA256     string `json:"payload_sha256"`
	CheckoutReference string `json:"checkout_reference,omitempty"`
}
type BillingResult struct {
	EventID   string `json:"event_id"`
	AccountID string `json:"account_id,omitempty"`
	State     string `json:"state"`
	Duplicate bool   `json:"duplicate"`
}
type BillingMapping struct {
	Provider       string    `json:"provider"`
	CustomerID     string    `json:"customer_id"`
	SubscriptionID string    `json:"subscription_id"`
	AccountID      string    `json:"account_id"`
	Version        int64     `json:"version"`
	Revision       int64     `json:"revision"`
	Plan           string    `json:"plan"`
	ProviderReadAt time.Time `json:"provider_read_at,omitempty"`
	stateDigest    string
}

func validMapping(m BillingMapping) bool {
	return boundedText(m.Provider, 32) && boundedText(m.CustomerID, 128) && boundedText(m.SubscriptionID, 128) && boundedText(m.AccountID, 128)
}
func (s *OperationsStore) BindBilling(ctx context.Context, p AdminPrincipal, m BillingMapping) error {
	if err := p.authorize(m.AccountID); err != nil {
		return err
	}
	if !validMapping(m) {
		return fmt.Errorf("invalid billing mapping")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	id, err := canonicalAccount(ctx, tx, m.AccountID)
	if err != nil {
		return err
	}
	if err = p.authorize(id); err != nil {
		return err
	}
	m.AccountID = id
	var conflicts int
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM ops_billing_mappings WHERE provider=? AND (customer_id=? OR subscription_id=?) AND NOT (customer_id=? AND subscription_id=? AND account_id=?)`, m.Provider, m.CustomerID, m.SubscriptionID, m.CustomerID, m.SubscriptionID, id).Scan(&conflicts)
	if err != nil {
		return err
	}
	if conflicts > 0 {
		return fmt.Errorf("conflicting subscription/account mapping")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ops_billing_mappings(provider,customer_id,subscription_id,account_id) VALUES(?,?,?,?) ON CONFLICT(provider,subscription_id) DO NOTHING`, m.Provider, m.CustomerID, m.SubscriptionID, id)
	if err != nil {
		return err
	}
	if err = projectBillingAccount(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit()
}
func readBillingMapping(ctx context.Context, q operationQuery, provider, sub string) (*BillingMapping, error) {
	m := &BillingMapping{Provider: provider, SubscriptionID: sub}
	var stamp int64
	var legacyReviewedAt string
	err := q.QueryRowContext(ctx, `SELECT m.customer_id,m.account_id,m.version,COALESCE(s.revision,0),COALESCE(s.plan,''),COALESCE(s.provider_read_at,0),COALESCE(s.digest,''),COALESCE((SELECT received_at FROM ops_billing_events e WHERE e.provider=m.provider AND e.subscription_id=m.subscription_id AND e.event_type='snapshot.reconciled' ORDER BY e.rowid DESC LIMIT 1),'') FROM ops_billing_mappings m LEFT JOIN ops_billing_states s USING(provider,subscription_id) WHERE m.provider=? AND m.subscription_id=?`, provider, sub).Scan(&m.CustomerID, &m.AccountID, &m.Version, &m.Revision, &m.Plan, &stamp, &m.stateDigest, &legacyReviewedAt)
	if stamp > 0 {
		m.ProviderReadAt = time.Unix(0, stamp).UTC()
	} else if err == nil && provider == "stripe" && legacyReviewedAt != "" {
		// Hash-only legacy reviews cannot confer Pro. Their commit time is a
		// conservative ordering floor: fresh evidence must follow that review.
		m.ProviderReadAt, err = time.Parse(time.RFC3339Nano, legacyReviewedAt)
	}
	return m, err
}

type BillingStatus struct {
	Mapping         *BillingMapping `json:"mapping"`
	PendingEventIDs []string        `json:"pending_event_ids"`
}

// AdminBillingStatus exposes mapping CAS state and up to 100 outstanding
// receipts for a scoped operator review; it never exposes webhook payloads.
func (s *OperationsStore) AdminBillingStatus(ctx context.Context, p AdminPrincipal, provider, subscription string) (*BillingStatus, error) {
	m, err := readBillingMapping(ctx, s.db, provider, subscription)
	if err != nil {
		return nil, err
	}
	if err = p.authorize(m.AccountID); err != nil {
		return nil, err
	}
	out := &BillingStatus{Mapping: m, PendingEventIDs: []string{}}
	rows, err := s.db.QueryContext(ctx, `SELECT event_id FROM ops_billing_events WHERE provider=? AND subscription_id=? AND customer_id=? AND outcome='reconciliation_required' ORDER BY received_at,event_id LIMIT 100`, provider, subscription, m.CustomerID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out.PendingEventIDs = append(out.PendingEventIDs, id)
	}
	return out, rows.Err()
}
func (s *OperationsStore) ProcessBillingEvent(ctx context.Context, e BillingEvent) (*BillingResult, error) {
	if !boundedText(e.Provider, 32) || !boundedText(e.ID, 128) || !boundedText(e.Type, 128) || len(e.CustomerID) > 128 || len(e.SubscriptionID) > 128 || len(e.CheckoutReference) > 128 || e.Revision < 0 || e.Plan != "" && e.Plan != "free" && e.Plan != "pro" {
		return nil, fmt.Errorf("invalid billing metadata")
	}
	if e.PayloadSHA256 != "" {
		if b, err := hex.DecodeString(e.PayloadSHA256); err != nil || len(b) != 32 {
			return nil, fmt.Errorf("invalid payload digest")
		}
	}
	// Stripe receipts are never an authoritative sequenced entitlement adapter.
	if e.Provider == "stripe" && e.Revision != 0 {
		return nil, fmt.Errorf("Stripe requires reviewed provider state")
	}
	fingerprint := e
	// The verified body digest already covers editable checkout references.
	// Excluding this new advisory field preserves legacy signed-receipt replay.
	if e.PayloadSHA256 != "" {
		fingerprint.CheckoutReference = ""
	}
	data, _ := json.Marshal(fingerprint)
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	out := &BillingResult{EventID: e.ID, State: "ignored"}
	var priorDigest string
	err = tx.QueryRowContext(ctx, `SELECT digest,account_id,outcome FROM ops_billing_events WHERE provider=? AND event_id=?`, e.Provider, e.ID).Scan(&priorDigest, &out.AccountID, &out.State)
	if err == nil {
		if priorDigest != digest {
			return nil, fmt.Errorf("event ID reused with conflicting metadata")
		}
		out.Duplicate = true
		return out, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if e.Supported {
		out.State = "reconciliation_required"
		m, lookupErr := readBillingMapping(ctx, tx, e.Provider, e.SubscriptionID)
		if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
			return nil, lookupErr
		}
		if lookupErr == nil {
			out.AccountID = m.AccountID
			if e.CustomerID == m.CustomerID && e.Revision > 0 && e.Plan != "" {
				switch {
				case e.Revision < m.Revision:
					out.State = "stale"
				case e.Revision == m.Revision && e.Plan == m.Plan:
					out.State = "current"
				case e.Revision > m.Revision:
					if err = writeBillingState(ctx, tx, e.Provider, e.SubscriptionID, e.Plan, e.Revision, time.Time{}, digest); err != nil {
						return nil, err
					}
					if _, err = tx.ExecContext(ctx, `UPDATE ops_billing_mappings SET revision=?,plan=?,version=version+1 WHERE provider=? AND subscription_id=?`, e.Revision, e.Plan, e.Provider, e.SubscriptionID); err != nil {
						return nil, err
					}
					if err = projectBillingAccount(ctx, tx, m.AccountID); err != nil {
						return nil, err
					}
					out.State = "applied"
				}
			}
		}
	}
	if out.AccountID == "" && e.Provider == "stripe" && e.Type == "checkout.session.completed" && e.Supported && e.CheckoutReference != "" {
		err = tx.QueryRowContext(ctx, `SELECT account_id FROM ops_checkout_intents WHERE reference=?`, e.CheckoutReference).Scan(&out.AccountID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ops_billing_events(provider,event_id,digest,event_type,subscription_id,customer_id,account_id,revision,plan,outcome,received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, e.Provider, e.ID, digest, e.Type, e.SubscriptionID, e.CustomerID, out.AccountID, e.Revision, e.Plan, out.State, s.now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// Supplied snapshots are trusted operator input from an authoritative provider
// read. ExpectedVersion prevents a reviewed dry run overwriting intervening work.
type BillingSnapshot struct {
	Provider        string   `json:"provider"`
	CustomerID      string   `json:"customer_id"`
	SubscriptionID  string   `json:"subscription_id"`
	AccountID       string   `json:"account_id"`
	ExpectedVersion int64    `json:"expected_version"`
	Revision        int64    `json:"revision"`
	Plan            string   `json:"plan"`
	EventIDs        []string `json:"event_ids,omitempty"`
	// Explicit operator evidence for the production reviewed-apply path.
	ProviderReadAt   time.Time `json:"provider_read_at,omitempty"`
	EvidenceSHA256   string    `json:"evidence_sha256,omitempty"`
	PriceID          string    `json:"price_id,omitempty"`
	ProviderStatus   string    `json:"provider_status,omitempty"`
	PaymentConfirmed bool      `json:"payment_confirmed,omitempty"`
}
type ReconciliationChange struct {
	BillingSnapshot
	CurrentPlan string `json:"current_plan"`
	State       string `json:"state"`
}

func reconciliationChange(ctx context.Context, tx *sql.Tx, p AdminPrincipal, snap BillingSnapshot) (*ReconciliationChange, error) {
	if err := p.authorize(snap.AccountID); err != nil {
		return nil, err
	}
	if !validMapping(BillingMapping{Provider: snap.Provider, CustomerID: snap.CustomerID, SubscriptionID: snap.SubscriptionID, AccountID: snap.AccountID}) || snap.Plan != "free" && snap.Plan != "pro" || snap.ExpectedVersion < 0 || snap.Revision < 0 {
		return nil, fmt.Errorf("invalid billing snapshot")
	}
	out := &ReconciliationChange{BillingSnapshot: snap, State: "reconciliation_required"}
	id, err := canonicalAccount(ctx, tx, snap.AccountID)
	if err != nil {
		return nil, err
	}
	if err = p.authorize(id); err != nil {
		return nil, err
	}
	out.AccountID = id
	out.CurrentPlan, _, err = billingAccountState(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	m, err := readBillingMapping(ctx, tx, snap.Provider, snap.SubscriptionID)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if m.CustomerID != snap.CustomerID || m.AccountID != id {
		return out, nil
	}
	if m.Version != snap.ExpectedVersion {
		out.State = "version_conflict"
		return out, nil
	}
	if snap.Provider == "stripe" {
		if snap.ProviderReadAt.IsZero() {
			return nil, fmt.Errorf("Stripe snapshot requires provider read time")
		}
		if !m.ProviderReadAt.IsZero() {
			if snap.ProviderReadAt.Before(m.ProviderReadAt) {
				out.State = "stale"
				return out, nil
			}
			if snap.ProviderReadAt.Equal(m.ProviderReadAt) && billingSnapshotStateDigest(snap) != m.stateDigest {
				return out, nil
			}
		}
	}
	if snap.Revision < m.Revision {
		out.State = "stale"
		return out, nil
	}
	if snap.Revision > 0 && snap.Revision == m.Revision && m.Plan != snap.Plan {
		return out, nil
	}
	if len(snap.EventIDs) > 100 {
		return nil, fmt.Errorf("at most 100 reviewed events per snapshot")
	}
	pending := false
	seen := map[string]bool{}
	for _, eventID := range snap.EventIDs {
		if !boundedText(eventID, 128) || seen[eventID] {
			return nil, fmt.Errorf("invalid or duplicate reviewed event ID")
		}
		seen[eventID] = true
		var customer, sub, account, outcome string
		err = tx.QueryRowContext(ctx, `SELECT customer_id,subscription_id,account_id,outcome FROM ops_billing_events WHERE provider=? AND event_id=?`, snap.Provider, eventID).Scan(&customer, &sub, &account, &outcome)
		if errors.Is(err, sql.ErrNoRows) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if customer != snap.CustomerID || sub != snap.SubscriptionID || account != "" && account != id || outcome != "reconciliation_required" && outcome != "reconciled" {
			return out, nil
		}
		if outcome == "reconciliation_required" {
			pending = true
		}
	}
	out.State = "change_expected"
	if m.Plan == snap.Plan && m.Revision == snap.Revision && m.ProviderReadAt.Equal(snap.ProviderReadAt) && !pending {
		out.State = "current"
	}
	return out, nil
}
func (s *OperationsStore) Reconcile(ctx context.Context, p AdminPrincipal, snapshots []BillingSnapshot, applyFixture bool) ([]ReconciliationChange, error) {
	return s.reconcile(ctx, p, snapshots, applyFixture, false)
}

// ApplyReviewedBilling is a local, authenticated operator action, never a
// webhook adapter. The operator must verify ownership and an approved price
// against a fresh Stripe read. Evidence is hashed into the immutable audit.
// CAS and a durable provider-read watermark prevent older reviews from winning.
func (s *OperationsStore) ApplyReviewedBilling(ctx context.Context, p AdminPrincipal, snapshots []BillingSnapshot) ([]ReconciliationChange, error) {
	for _, snap := range snapshots {
		digest, err := hex.DecodeString(snap.EvidenceSHA256)
		age := s.now().Sub(snap.ProviderReadAt)
		if snap.Provider != "stripe" || snap.Revision != 0 || len(snap.EventIDs) == 0 || err != nil || len(digest) != sha256.Size || snap.ProviderReadAt.IsZero() || age < 0 || age > 5*time.Minute || !boundedText(snap.PriceID, 128) {
			return nil, fmt.Errorf("reviewed apply requires fresh Stripe evidence, price and event receipts; revision must be zero")
		}
		if err := validateStripeEntitlement(snap); err != nil {
			return nil, err
		}
	}
	return s.reconcile(ctx, p, snapshots, false, true)
}

func (s *OperationsStore) reconcile(ctx context.Context, p AdminPrincipal, snapshots []BillingSnapshot, applyFixture, applyReviewed bool) ([]ReconciliationChange, error) {
	if len(snapshots) == 0 || len(snapshots) > 1000 {
		return nil, fmt.Errorf("require 1..1000 snapshots")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if applyFixture {
		var marker string
		if err = tx.QueryRowContext(ctx, `SELECT value FROM ops_fixture WHERE id=1`).Scan(&marker); err != nil || marker != "disposable-local" {
			return nil, fmt.Errorf("apply requires a disposable local fixture database")
		}
	}
	out := make([]ReconciliationChange, 0, len(snapshots))
	seen := map[string]bool{}
	for _, snap := range snapshots {
		key := snap.Provider + "/" + snap.SubscriptionID
		if seen[key] {
			return nil, fmt.Errorf("duplicate subscription snapshot")
		}
		seen[key] = true
		if snap.Provider == "stripe" {
			if err := validateStripeEntitlement(snap); err != nil {
				return nil, err
			}
		} else if (applyFixture || applyReviewed) && snap.Revision == 0 {
			return nil, fmt.Errorf("verified billing requires an authoritative revision or provider read")
		}
		change, err := reconciliationChange(ctx, tx, p, snap)
		if err != nil {
			return nil, err
		}
		out = append(out, *change)
		if (applyFixture || applyReviewed) && change.State != "current" && change.State != "change_expected" {
			return nil, fmt.Errorf("snapshot cannot apply: %s", change.State)
		}
	}
	if !applyFixture && !applyReviewed {
		return out, nil
	}
	for i := range out {
		c := &out[i]
		if c.State == "current" {
			continue
		}
		if err = writeBillingState(ctx, tx, c.Provider, c.SubscriptionID, c.Plan, c.Revision, c.ProviderReadAt, billingSnapshotStateDigest(c.BillingSnapshot)); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE ops_billing_mappings SET plan=?,revision=?,version=version+1 WHERE provider=? AND subscription_id=?`, c.Plan, c.Revision, c.Provider, c.SubscriptionID); err != nil {
			return nil, err
		}
		// Reconciliation is separately auditable; it never clears suspension.
		reconciliationID := "reconcile:" + uuid.NewString()
		data, _ := json.Marshal(c.BillingSnapshot)
		sum := sha256.Sum256(data)
		if _, err = tx.ExecContext(ctx, `INSERT INTO ops_billing_events(provider,event_id,digest,event_type,subscription_id,customer_id,account_id,revision,plan,outcome,received_at,actor) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, c.Provider, reconciliationID, hex.EncodeToString(sum[:]), "snapshot.reconciled", c.SubscriptionID, c.CustomerID, c.AccountID, c.Revision, c.Plan, "reconciled", s.now().UTC().Format(time.RFC3339Nano), p.actor); err != nil {
			return nil, err
		}
		for _, eventID := range c.EventIDs {
			if _, err = tx.ExecContext(ctx, `UPDATE ops_billing_events SET account_id=?,outcome='reconciled',reconciled_by=? WHERE provider=? AND event_id=? AND outcome='reconciliation_required'`, c.AccountID, reconciliationID, c.Provider, eventID); err != nil {
				return nil, err
			}
		}
		c.State = "applied"
	}
	accounts := map[string]bool{}
	for _, c := range out {
		accounts[c.AccountID] = true
	}
	for id := range accounts {
		if err = projectBillingAccount(ctx, tx, id); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// The fingerprint excludes local CAS, receipt selection and account UUID, which
// can change during a merge. Equal provider order may only confirm equal state.
func billingSnapshotStateDigest(s BillingSnapshot) string {
	s.ExpectedVersion, s.AccountID, s.EventIDs = 0, "", nil
	s.ProviderReadAt = s.ProviderReadAt.UTC()
	data, _ := json.Marshal(s)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validateStripeEntitlement(s BillingSnapshot) error {
	switch s.ProviderStatus {
	case "active", "trialing", "canceled", "unpaid", "past_due", "incomplete", "incomplete_expired", "paused":
	default:
		return fmt.Errorf("unknown reviewed subscription status")
	}
	plan := "free"
	if s.ProviderStatus == "active" && s.PaymentConfirmed {
		plan = "pro"
	}
	if s.Plan != plan {
		return fmt.Errorf("plan must match reviewed subscription and payment eligibility")
	}
	return nil
}
