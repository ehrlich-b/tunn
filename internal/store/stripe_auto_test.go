package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStripeAutomationPriceIDs(t *testing.T) {
	for _, tc := range []struct {
		name, price string
		valid       bool
	}{
		{"alphanumeric", "price_1AbC09", true},
		{"maximum-length", "price_" + strings.Repeat("a", 122), true},
		{"too-long", "price_" + strings.Repeat("a", 123), false},
		{"missing", "", false},
		{"wrong-prefix", "prod_1AbC09", false},
		{"prefix-only", "price_", false},
		{"punctuation", "price_!!!", false},
		{"underscore", "price_fixture_month", false},
		{"space", "price_a b", false},
		{"newline", "price_a\n", false},
		{"unicode", "price_é123", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auto := NewStripeAutomation("sk_fixture", []string{tc.price}, nil)
			if auto.Configured() != tc.valid || auto.prices[tc.price] != tc.valid {
				t.Fatalf("configured = %v, want %v", auto.Configured(), tc.valid)
			}
		})
	}
	auto := NewStripeAutomation("sk_fixture", []string{"price_!!!", "price_1AbC09"}, nil)
	if !auto.Configured() || len(auto.prices) != 1 || !auto.prices["price_1AbC09"] {
		t.Fatal("only valid approved IDs may enable automation")
	}
	if NewStripeAutomation("", []string{"price_1AbC09"}, nil).Configured() {
		t.Fatal("an API key is still required")
	}
}

type autoStripeFixture struct {
	t          *testing.T
	db         *sql.DB
	ops        *OperationsStore
	account    *Account
	automation *StripeAutomation
	sub        stripeCurrentSubscription
	event      BillingEvent
	reads      int
	fail       bool
	beforeRead func()
}

func newAutoStripeFixture(t *testing.T, bound bool) *autoStripeFixture {
	t.Helper()
	db, ops, account, _ := operationsFixture(t)
	f := &autoStripeFixture{t: t, db: db, ops: ops, account: account}
	now := ops.now().UTC()
	f.sub.ID, f.sub.Customer, f.sub.Status = "sub_auto", "cus_auto", "active"
	f.sub.PeriodStart, f.sub.PeriodEnd = now.Unix()-1, now.Add(30*24*time.Hour).Unix()
	// Decode a real API-shaped fixture rather than constructing payment truth
	// in the event. The signed notification contains no price/payment evidence.
	payload := fmt.Sprintf(`{"id":"sub_auto","customer":"cus_auto","status":"active","current_period_start":%d,"current_period_end":%d,"items":{"data":[{"price":{"id":"price_approved"}}]},"latest_invoice":{"id":"in_auto","customer":"cus_auto","subscription":"sub_auto","status":"paid","paid":true,"amount_paid":2000,"amount_remaining":0,"charge":{"id":"ch_auto","customer":"cus_auto","invoice":"in_auto","paid":true,"amount_refunded":0,"disputed":false},"lines":{"data":[{"type":"subscription","subscription":"sub_auto","price":{"id":"price_approved"},"period":{"start":%d,"end":%d}}]}}}`, f.sub.PeriodStart, f.sub.PeriodEnd, f.sub.PeriodStart, f.sub.PeriodEnd)
	if err := json.Unmarshal([]byte(payload), &f.sub); err != nil {
		t.Fatal(err)
	}
	if bound {
		if err := ops.BindBilling(context.Background(), operationsPrincipal(t, account.ID), BillingMapping{Provider: "stripe", SubscriptionID: f.sub.ID, CustomerID: f.sub.Customer, AccountID: account.ID}); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := ops.BeginBillingCheckout(context.Background(), account.ID)
	if bound {
		ref = ""
	} else if err != nil {
		t.Fatal(err)
	}
	f.event = BillingEvent{Provider: "stripe", ID: "evt_auto", Type: "checkout.session.completed", CustomerID: f.sub.Customer, SubscriptionID: f.sub.ID, CheckoutReference: ref, SessionID: "cs_auto", CompletedAt: now.Unix(), Supported: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.reads++
		key, secret, ok := r.BasicAuth()
		if !ok || key != "sk_test_fixture" || secret != "" || r.Method != "GET" || r.Header.Get("Stripe-Version") != "2024-06-20" {
			t.Error("unexpected provider request")
		}
		if f.fail {
			w.WriteHeader(503)
			return
		}
		switch r.URL.Path {
		case "/subscriptions/sub_auto":
			if r.URL.Query().Get("expand[]") != "latest_invoice.charge" {
				t.Error("missing expansion")
			}
			if f.beforeRead != nil {
				fn := f.beforeRead
				f.beforeRead = nil
				fn()
			}
			_ = json.NewEncoder(w).Encode(f.sub)
		case "/charges/ch_auto":
			_ = json.NewEncoder(w).Encode(f.sub.Invoice.Charge)
		case "/invoices/in_auto":
			_ = json.NewEncoder(w).Encode(map[string]any{"subscription": f.sub.ID, "customer": f.sub.Customer})
		default:
			t.Errorf("unexpected provider read %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	f.automation = NewStripeAutomation("sk_test_fixture", []string{"price_approved"}, nil)
	f.automation.base = server.URL
	f.automation.client = server.Client()
	return f
}
func (f *autoStripeFixture) send(e BillingEvent) *BillingResult {
	f.t.Helper()
	now := f.ops.now().Add(time.Millisecond)
	f.ops.now = func() time.Time { return now }
	out, err := f.automation.Process(context.Background(), f.ops, e)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}
func (f *autoStripeFixture) audits(want int) {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM ops_billing_events WHERE event_type='snapshot.reconciled' AND actor='system:stripe'`).Scan(&n); err != nil || n != want {
		f.t.Fatalf("audits=%d want=%d error=%v", n, want, err)
	}
}
func (f *autoStripeFixture) pending(e BillingEvent) {
	f.t.Helper()
	var outcome string
	if err := f.db.QueryRow(`SELECT outcome FROM ops_billing_events WHERE event_id=?`, e.ID).Scan(&outcome); err != nil || outcome != "reconciliation_required" {
		f.t.Fatalf("pending receipt=%s %v", outcome, err)
	}
}

func TestAutoActivationHappyPathAndReplayedWebhook(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(fmt.Sprint("bound=", bound), func(t *testing.T) {
			f := newAutoStripeFixture(t, bound)
			event := f.event
			if bound {
				event.Type = "customer.subscription.created"
			}
			out := f.send(event)
			if out.State != "reconciled" || out.AccountID != f.account.ID {
				t.Fatalf("%+v", out)
			}
			requirePlan(t, f.db, f.account.ID, "pro")
			f.audits(1)
			reads := f.reads
			replay := f.send(event)
			if !replay.Duplicate || replay.State != "reconciled" || f.reads != reads {
				t.Fatalf("replay=%+v reads=%d", replay, f.reads)
			}
			f.audits(1)
			// A separate receipt with unchanged authoritative state advances only the
			// watermark; it must not advance CAS or append another activation audit.
			event.ID, event.Type = "evt_same", "customer.subscription.updated"
			f.send(event)
			f.audits(1)
			m, err := readBillingMapping(context.Background(), f.db, "stripe", f.sub.ID)
			if err != nil || m.Version != 1 {
				t.Fatalf("mapping=%+v %v", m, err)
			}
		})
	}
}
func TestAutoActivationOutOfOrderEventsAndCancellation(t *testing.T) {
	f := newAutoStripeFixture(t, false)
	// A lifecycle notification arriving before its ownership receipt cannot bind.
	early := f.event
	early.ID, early.Type = "evt_early", "customer.subscription.updated"
	f.send(early)
	requirePlan(t, f.db, f.account.ID, "free")
	f.pending(early)
	f.send(f.event)
	requirePlan(t, f.db, f.account.ID, "pro")
	// A scheduled cancellation is still active for the paid current period.
	f.sub.CancelAtPeriodEnd = true
	scheduled := f.event
	scheduled.ID, scheduled.Type = "evt_cancel_scheduled", "customer.subscription.updated"
	f.send(scheduled)
	requirePlan(t, f.db, f.account.ID, "pro")
	f.audits(1)
	f.sub.Status = "canceled"
	ended := f.event
	ended.ID, ended.Type = "evt_ended", "customer.subscription.deleted"
	f.send(ended)
	requirePlan(t, f.db, f.account.ID, "free")
	f.audits(2)
	// Older "active" event body/order cannot override the current canceled read.
	stale := f.event
	stale.ID, stale.Type = "evt_old_created", "customer.subscription.created"
	f.send(stale)
	requirePlan(t, f.db, f.account.ID, "free")
	f.audits(2)
	f.send(f.event)
	f.send(ended)
	requirePlan(t, f.db, f.account.ID, "free")
	f.audits(2)
}
func TestAutoActivationUnknownPriceAndStripeReadFailure(t *testing.T) {
	for _, test := range []string{"unknown_price", "read_failure", "disabled_allowlist", "disabled_key"} {
		t.Run(test, func(t *testing.T) {
			f := newAutoStripeFixture(t, false)
			switch test {
			case "unknown_price":
				f.sub.Items.Data[0].Price.ID = "price_unreviewed"
			case "read_failure":
				f.fail = true
			case "disabled_allowlist":
				f.automation.prices = nil
			case "disabled_key":
				f.automation.key = ""
			}
			f.send(f.event)
			requirePlan(t, f.db, f.account.ID, "free")
			f.pending(f.event)
			f.audits(0)
			if test == "read_failure" {
				f.fail = false
				f.send(f.event)
				requirePlan(t, f.db, f.account.ID, "pro")
				f.audits(1)
			}
		})
	}
}
func TestAutoActivationCurrentPeriodPaymentProof(t *testing.T) {
	tests := map[string]func(*autoStripeFixture){
		"trial":                  func(f *autoStripeFixture) { f.sub.Status = "trialing" },
		"past_period":            func(f *autoStripeFixture) { f.sub.PeriodEnd = f.ops.now().Add(-time.Second).Unix() },
		"unpaid":                 func(f *autoStripeFixture) { f.sub.Invoice.Paid = false },
		"zero_paid":              func(f *autoStripeFixture) { f.sub.Invoice.AmountPaid = 0 },
		"manual_paid":            func(f *autoStripeFixture) { f.sub.Invoice.PaidOutOfBand = true },
		"previous_invoice":       func(f *autoStripeFixture) { f.sub.Invoice.Lines.Data[0].Period.Start-- },
		"wrong_invoice_price":    func(f *autoStripeFixture) { f.sub.Invoice.Lines.Data[0].Price.ID = "price_unknown" },
		"wrong_customer":         func(f *autoStripeFixture) { f.sub.Customer = "cus_other" },
		"wrong_invoice_customer": func(f *autoStripeFixture) { f.sub.Invoice.Customer = "cus_other" },
		"truncated_items":        func(f *autoStripeFixture) { f.sub.Items.HasMore = true },
		"truncated_lines":        func(f *autoStripeFixture) { f.sub.Invoice.Lines.HasMore = true },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newAutoStripeFixture(t, false)
			mutate(f)
			f.send(f.event)
			requirePlan(t, f.db, f.account.ID, "free")
			f.pending(f.event)
			f.audits(0)
		})
	}
}
func TestAutoActivationIntentQuarantineAndSuspension(t *testing.T) {
	for _, name := range []string{"unbound", "unknown_reference", "late", "unknown_time", "duplicate", "suspended", "late_delivery"} {
		t.Run(name, func(t *testing.T) {
			f := newAutoStripeFixture(t, false)
			e := f.event
			switch name {
			case "unbound":
				e.Type = "customer.subscription.updated"
			case "unknown_reference":
				e.CheckoutReference = "editable-unknown-reference"
			case "late":
				e.CompletedAt += int64(25 * time.Hour / time.Second)
			case "unknown_time":
				e.CompletedAt = 0
			case "duplicate":
				// First payment consumes the intent, but unknown price keeps it pending.
				f.sub.Items.Data[0].Price.ID = "price_unknown"
				f.send(e)
				e.ID, e.SubscriptionID, e.SessionID = "evt_second", "sub_second", "cs_second"
			case "suspended":
				if _, err := f.ops.Transition(context.Background(), operationsPrincipal(t, f.account.ID), f.account.ID, "suspended", "operator hold", 0); err != nil {
					t.Fatal(err)
				}
			case "late_delivery":
				issued := f.ops.now()
				f.ops.now = func() time.Time { return issued.Add(25 * time.Hour) }
			}
			f.send(e)
			if name == "suspended" || name == "late_delivery" {
				requirePlan(t, f.db, f.account.ID, "pro")
				f.audits(1)
				if name == "suspended" {
					status, err := f.ops.LookupAccountStatus(context.Background(), f.account.ID)
					if err != nil || status.State != "suspended" || status.Version != 1 {
						t.Fatal(status, err)
					}
				}
			} else {
				requirePlan(t, f.db, f.account.ID, "free")
				f.audits(0)
			}
			if name == "duplicate" {
				var outcome string
				if err := f.db.QueryRow(`SELECT outcome FROM ops_checkout_payments WHERE subscription_id='sub_second'`).Scan(&outcome); err != nil || outcome != "duplicate_payment_refund_needed" {
					t.Fatal(outcome, err)
				}
			}
			if name == "unknown_time" {
				life := e
				life.ID, life.Type = "evt_lifecycle", "customer.subscription.updated"
				f.send(life)
				requirePlan(t, f.db, f.account.ID, "free")
			}
		})
	}
}
func TestAutoActivationRefundAndDispute(t *testing.T) {
	for _, typ := range []string{"charge.refunded", "charge.dispute.created"} {
		t.Run(typ, func(t *testing.T) {
			f := newAutoStripeFixture(t, false)
			f.send(f.event)
			requirePlan(t, f.db, f.account.ID, "pro")
			if typ == "charge.refunded" {
				f.sub.Invoice.Charge.AmountRefunded = 2000
			} else {
				f.sub.Invoice.Charge.Disputed = true
			}
			e := BillingEvent{Provider: "stripe", ID: "evt_revoke", Type: typ, ChargeID: "ch_auto", Supported: true}
			f.send(e)
			requirePlan(t, f.db, f.account.ID, "free")
			f.audits(2)
			f.send(e)
			f.send(f.event)
			requirePlan(t, f.db, f.account.ID, "free")
			f.audits(2)
			older := f.event
			older.ID, older.Type = "evt_reordered", "customer.subscription.updated"
			f.send(older)
			requirePlan(t, f.db, f.account.ID, "free")
			f.audits(2)
		})
	}
}
func TestAutoActivationCASAndAuditRollback(t *testing.T) {
	t.Run("CAS", func(t *testing.T) {
		f := newAutoStripeFixture(t, true)
		f.beforeRead = func() {
			if _, err := f.db.Exec(`UPDATE ops_billing_mappings SET version=version+1`); err != nil {
				t.Fatal(err)
			}
		}
		e := f.event
		e.Type = "customer.subscription.updated"
		f.send(e)
		requirePlan(t, f.db, f.account.ID, "free")
		f.pending(e)
		f.audits(0)
	})
	t.Run("audit_rollback", func(t *testing.T) {
		f := newAutoStripeFixture(t, false)
		if _, err := f.db.Exec(`CREATE TRIGGER auto_audit_failure BEFORE INSERT ON ops_billing_events WHEN NEW.actor='system:stripe' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`); err != nil {
			t.Fatal(err)
		}
		_, err := f.automation.Process(context.Background(), f.ops, f.event)
		if err == nil || !strings.Contains(err.Error(), "fixture audit failure") {
			t.Fatal(err)
		}
		requirePlan(t, f.db, f.account.ID, "free")
		f.pending(f.event)
		f.audits(0)
		var mappings, states int
		if err = f.db.QueryRow(`SELECT (SELECT count(*) FROM ops_billing_mappings),(SELECT count(*) FROM ops_billing_states)`).Scan(&mappings, &states); err != nil || mappings != 0 || states != 0 {
			t.Fatal(mappings, states, err)
		}
	})
}

func TestAutoActivationPreservesOtherEntitlements(t *testing.T) {
	f := newAutoStripeFixture(t, false)
	f.send(f.event)
	// A preserved grant arriving through a merge remains independent of Stripe.
	if _, err := f.db.Exec(`INSERT INTO ops_legacy_entitlements(original_account_id,account_id,plan) VALUES(?,?,'pro')`, f.account.ID, f.account.ID); err != nil {
		t.Fatal(err)
	}
	f.sub.Status = "canceled"
	ended := f.event
	ended.ID, ended.Type = "evt_end_with_legacy", "customer.subscription.deleted"
	f.send(ended)
	requirePlan(t, f.db, f.account.ID, "pro")
	f.audits(2)
	ended.ID = "evt_unchanged_end"
	f.send(ended)
	requirePlan(t, f.db, f.account.ID, "pro")
	f.audits(2)
	m, err := readBillingMapping(context.Background(), f.db, "stripe", f.sub.ID)
	if err != nil || m.Plan != "free" || m.Version != 2 {
		t.Fatal(m, err)
	}
}
