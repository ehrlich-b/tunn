package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
)

// StripeAutomation is installed only at the database authority. Incoming node
// metadata cannot supply a snapshot, price approval or payment confirmation.
// Serialize current reads through commit; operator writes still compete via CAS.
type StripeAutomation struct {
	mu     sync.Mutex
	key    string
	prices map[string]bool
	client *http.Client
	base   string
}

// Price IDs have a price_ prefix followed by ASCII letters and digits. Keep this
// shape and bound in sync with scripts/check-billing-ready.sh.
var stripePriceIDPattern = regexp.MustCompile(`^price_[A-Za-z0-9]+$`)

func NewStripeAutomation(key string, prices []string, transport http.RoundTripper) *StripeAutomation {
	approved := make(map[string]bool)
	for _, price := range prices {
		if len(price) <= 128 && stripePriceIDPattern.MatchString(price) {
			approved[price] = true
		}
	}
	return &StripeAutomation{key: key, prices: approved, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: "https://api.stripe.com/v1"}
}

// Configured reports whether automatic activation has its local prerequisites.
// It does not verify provider credentials, price ownership or payment evidence.
func (a *StripeAutomation) Configured() bool {
	return a.key != "" && len(a.prices) != 0
}

// Use a fixed API version: the invoice/charge association and subscription
// billing period used below are the 2024-06-20 resource shapes.
func (a *StripeAutomation) get(ctx context.Context, path string, out any) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(a.key, "")
	req.Header.Set("Stripe-Version", "2024-06-20")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 262145))
	if err != nil || len(body) > 262144 || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Stripe read unavailable")
	}
	if err = json.Unmarshal(body, out); err != nil {
		return nil, err
	}
	return body, nil
}

type stripeCharge struct {
	ID             string `json:"id"`
	Customer       string `json:"customer"`
	Invoice        string `json:"invoice"`
	Paid           bool   `json:"paid"`
	Disputed       bool   `json:"disputed"`
	AmountRefunded int64  `json:"amount_refunded"`
}
type stripeInvoice struct {
	ID              string        `json:"id"`
	Customer        string        `json:"customer"`
	Subscription    string        `json:"subscription"`
	Status          string        `json:"status"`
	Paid            bool          `json:"paid"`
	PaidOutOfBand   bool          `json:"paid_out_of_band"`
	AmountPaid      int64         `json:"amount_paid"`
	AmountRemaining int64         `json:"amount_remaining"`
	Charge          *stripeCharge `json:"charge"`
	Lines           struct {
		HasMore bool `json:"has_more"`
		Data    []struct {
			Type         string `json:"type"`
			Subscription string `json:"subscription"`
			Price        struct {
				ID string `json:"id"`
			} `json:"price"`
			Period struct {
				Start int64 `json:"start"`
				End   int64 `json:"end"`
			} `json:"period"`
		} `json:"data"`
	} `json:"lines"`
}
type stripeCurrentSubscription struct {
	ID                string `json:"id"`
	Customer          string `json:"customer"`
	Status            string `json:"status"`
	Livemode          bool   `json:"livemode"`
	CancelAtPeriodEnd bool   `json:"cancel_at_period_end"`
	PeriodStart       int64  `json:"current_period_start"`
	PeriodEnd         int64  `json:"current_period_end"`
	Items             struct {
		HasMore bool `json:"has_more"`
		Data    []struct {
			Price struct {
				ID string `json:"id"`
			} `json:"price"`
		} `json:"data"`
	} `json:"items"`
	Invoice *stripeInvoice `json:"latest_invoice"`
}

func (a *StripeAutomation) chargeSubscription(ctx context.Context, e BillingEvent) (string, error) {
	if e.ChargeID != "" {
		var charge stripeCharge
		if _, err := a.get(ctx, "/charges/"+url.PathEscape(e.ChargeID), &charge); err != nil {
			return "", err
		}
		if charge.ID != e.ChargeID || charge.Invoice == "" || charge.Customer == "" {
			return "", fmt.Errorf("unassociated charge")
		}
		var invoice struct {
			Subscription string `json:"subscription"`
			Customer     string `json:"customer"`
		}
		if _, err := a.get(ctx, "/invoices/"+url.PathEscape(charge.Invoice), &invoice); err != nil {
			return "", err
		}
		if invoice.Customer != charge.Customer {
			return "", fmt.Errorf("invoice ownership mismatch")
		}
		return invoice.Subscription, nil
	}
	return e.SubscriptionID, nil
}

// read obtains current state even for old or replayed notifications. A refund
// or dispute is associated through provider reads, never editable metadata.
func (a *StripeAutomation) read(ctx context.Context, e BillingEvent, now time.Time) (*BillingSnapshot, error) {
	subID := e.SubscriptionID
	if subID == "" {
		return nil, fmt.Errorf("unassociated subscription")
	}
	var sub stripeCurrentSubscription
	body, err := a.get(ctx, "/subscriptions/"+url.PathEscape(subID)+"?expand[]=latest_invoice.charge", &sub)
	if err != nil {
		return nil, err
	}
	if sub.ID != subID || sub.Customer == "" || e.CustomerID != "" && sub.Customer != e.CustomerID || sub.Items.HasMore || len(sub.Items.Data) != 1 {
		return nil, fmt.Errorf("subscription ownership or items mismatch")
	}
	price := sub.Items.Data[0].Price.ID
	if !a.prices[price] {
		return nil, fmt.Errorf("unapproved price")
	}
	sum := sha256.Sum256(body)
	snap := &BillingSnapshot{Provider: "stripe", CustomerID: sub.Customer, SubscriptionID: sub.ID, PriceID: price, ProviderStatus: sub.Status, ProviderReadAt: now, EvidenceSHA256: hex.EncodeToString(sum[:]), Plan: "free"}
	if sub.Status == "canceled" {
		return snap, nil
	}
	// Non-active and incomplete evidence stay with the operator. Scheduling
	// cancellation leaves the active paid period intact until Stripe ends it.
	if sub.Status != "active" || sub.PeriodStart > now.Unix() || sub.PeriodEnd <= now.Unix() || sub.PeriodStart <= 0 {
		return nil, fmt.Errorf("not a current active period")
	}
	inv := sub.Invoice
	if inv == nil || inv.ID == "" || inv.Subscription != sub.ID || inv.Customer != sub.Customer || inv.Status != "paid" || !inv.Paid || inv.PaidOutOfBand || inv.AmountPaid <= 0 || inv.AmountRemaining != 0 || inv.Lines.HasMore || len(inv.Lines.Data) != 1 {
		return nil, fmt.Errorf("current period payment unverified")
	}
	line := inv.Lines.Data[0]
	if line.Type != "subscription" || line.Subscription != sub.ID || line.Price.ID != price || line.Period.Start != sub.PeriodStart || line.Period.End != sub.PeriodEnd {
		return nil, fmt.Errorf("invoice period or price mismatch")
	}
	charge := inv.Charge
	if charge == nil || charge.ID == "" || !charge.Paid || charge.Customer != sub.Customer || charge.Invoice != inv.ID {
		return nil, fmt.Errorf("charge unverified")
	}
	if e.ChargeID != "" && e.ChargeID != charge.ID {
		return nil, fmt.Errorf("notification is for another billing period")
	}
	snap.PaymentConfirmed = charge.AmountRefunded == 0 && !charge.Disputed
	if snap.PaymentConfirmed {
		snap.Plan = "pro"
	}
	return snap, nil
}

// Process commits the existing receipt/intent ledger first. Failed reads and
// anomalies leave that queue intact; storage failures are retryable. No raw
// Stripe response or API credential is persisted or forwarded over node RPC.
func (a *StripeAutomation) Process(ctx context.Context, s *OperationsStore, e BillingEvent) (*BillingResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out, err := s.ProcessBillingEvent(ctx, e)
	if err != nil || e.Provider != "stripe" || !e.Supported || out.State != "reconciliation_required" || !a.Configured() {
		return out, err
	}
	switch e.Type {
	case "checkout.session.completed", "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted", "invoice.paid", "invoice.payment_succeeded", "charge.refunded", "charge.dispute.created":
	default:
		return out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if e.ChargeID != "" {
		subID, err := a.chargeSubscription(ctx, e)
		if err != nil {
			return out, nil
		}
		e.SubscriptionID = subID
	}
	// Capture local CAS before the provider read, so a later operator action can
	// never be overwritten by evidence acquired for an older local version.
	before, lookup := readBillingMapping(ctx, s.db, "stripe", e.SubscriptionID)
	if lookup != nil && !errors.Is(lookup, sql.ErrNoRows) {
		return nil, lookup
	}
	readAt := s.now().UTC()
	snap, readErr := a.read(ctx, e, readAt)
	if readErr != nil {
		return out, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	m, err := readBillingMapping(ctx, tx, "stripe", snap.SubscriptionID)
	if errors.Is(err, sql.ErrNoRows) {
		// Only a consumed, on-time, server-issued intent can create ownership.
		// Lifecycle events without a prior checkout or explicit binding stay queued.
		var account, reference, session string
		var completed int64
		err = tx.QueryRowContext(ctx, `SELECT account_id,COALESCE(reference,''),completed_at,session_id FROM ops_checkout_payments WHERE provider='stripe' AND subscription_id=? AND customer_id=? AND outcome='accepted' AND resolution=''`, snap.SubscriptionID, snap.CustomerID).Scan(&account, &reference, &completed, &session)
		if errors.Is(err, sql.ErrNoRows) || err == nil && (account == "" || reference == "" || completed == 0 || session == "") {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if err = checkoutSubscriptionCanGrant(ctx, tx, "stripe", snap.SubscriptionID); err != nil {
			return out, nil
		}
		if err = stripeAdditionalPurchaseCanGrant(ctx, tx, account, snap.SubscriptionID); err != nil {
			return out, nil
		}
		var conflict bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ops_billing_mappings WHERE provider='stripe' AND customer_id=?)`, snap.CustomerID).Scan(&conflict); err != nil {
			return nil, err
		}
		if conflict {
			return out, nil
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO ops_billing_mappings(provider,customer_id,subscription_id,account_id) VALUES('stripe',?,?,?)`, snap.CustomerID, snap.SubscriptionID, account); err != nil {
			return nil, err
		}
		m, err = readBillingMapping(ctx, tx, "stripe", snap.SubscriptionID)
	} else if err == nil {
		if lookup != nil || before.Version != m.Version {
			return out, nil
		}
	}
	if err != nil {
		return nil, err
	}
	if m.CustomerID != snap.CustomerID || !m.ProviderReadAt.IsZero() && !readAt.After(m.ProviderReadAt) {
		return out, nil
	}
	var unknownCompletion bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ops_checkout_payments WHERE provider='stripe' AND subscription_id=? AND completed_at=0 AND resolution='')`, snap.SubscriptionID).Scan(&unknownCompletion); err != nil {
		return nil, err
	}
	if unknownCompletion {
		return out, nil
	}
	if err = checkoutSubscriptionCanGrant(ctx, tx, "stripe", snap.SubscriptionID); err != nil {
		return out, nil
	}
	if snap.Plan == "pro" {
		if err = stripeAdditionalPurchaseCanGrant(ctx, tx, m.AccountID, snap.SubscriptionID); err != nil {
			return out, nil
		}
	}
	snap.AccountID, snap.ExpectedVersion = m.AccountID, m.Version
	if err = validateStripeEntitlement(*snap); err != nil {
		return out, nil
	}
	// Reuse reconciliation validation for CAS, payment approvals, ownership and
	// the provider-read watermark, then write receipt/state/audit atomically.
	if e.ChargeID == "" {
		snap.EventIDs = []string{e.ID}
	}
	principal := AdminPrincipal{actor: "system:stripe", accounts: []string{m.AccountID}}
	change, err := reconciliationChange(ctx, tx, principal, *snap)
	if err != nil || change.State != "change_expected" {
		return out, nil
	}
	if err = writeBillingState(ctx, tx, "stripe", snap.SubscriptionID, snap.Plan, 0, readAt, billingSnapshotStateDigest(*snap)); err != nil {
		return nil, err
	}
	auditID := ""
	// A reviewed payment approval may require a fresh version even when its
	// old subscription state had the same plan. Other subscriptions and legacy
	// grants do not cause another audit for this unchanged subscription.
	var needsApprovalVersion bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ops_checkout_payments WHERE provider='stripe' AND subscription_id=? AND resolution='approved' AND approval_version>=?)`, snap.SubscriptionID, m.Version).Scan(&needsApprovalVersion); err != nil {
		return nil, err
	}
	if m.Plan != snap.Plan || needsApprovalVersion {
		auditID = "auto:" + uuid.NewString()
		data, _ := json.Marshal(snap)
		hash := sha256.Sum256(data)
		if _, err = tx.ExecContext(ctx, `UPDATE ops_billing_mappings SET plan=?,revision=0,version=version+1 WHERE provider='stripe' AND subscription_id=? AND version=?`, snap.Plan, snap.SubscriptionID, m.Version); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO ops_billing_events(provider,event_id,digest,event_type,subscription_id,customer_id,account_id,revision,plan,outcome,received_at,actor) VALUES('stripe',?,?,'snapshot.reconciled',?,?,?,0,?,'reconciled',?,'system:stripe')`, auditID, hex.EncodeToString(hash[:]), snap.SubscriptionID, snap.CustomerID, m.AccountID, snap.Plan, s.now().UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE ops_billing_events SET customer_id=?,subscription_id=?,account_id=?,outcome='reconciled',reconciled_by=? WHERE provider='stripe' AND event_id=? AND outcome='reconciliation_required'`, snap.CustomerID, snap.SubscriptionID, m.AccountID, auditID, e.ID); err != nil {
		return nil, err
	}
	if err = projectBillingAccount(ctx, tx, m.AccountID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	out.AccountID, out.State = m.AccountID, "reconciled"
	return out, nil
}
