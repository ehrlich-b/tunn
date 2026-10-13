package host

import (
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

// Regression tests ported from the independent revenue review of 578f52a.
// Each of the six reviewed scenarios must now preserve safe billing behavior.
// All accounts, provider IDs, receipts and payment evidence are synthetic.
func reviewRevenueFixture(t *testing.T) (*sql.DB, *ProxyServer, *storage.LocalStorage, *storage.Account) {
	t.Helper()
	db, err := store.OpenLocal(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	local := storage.NewLocalStorage(db)
	a, err := local.FindOrCreateByEmails(context.Background(), []string{"owner+demo@example.com"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	p := &ProxyServer{Domain: "tunn.to", storage: local, config: &config.Config{Environment: config.EnvProd, Domain: "tunn.to", JWTSecret: "fixture-revenue-signing-key", BillingEnabled: true, StripeWebhookSecret: "whsec_fixture", StripeCheckoutURLMonthly: "https://buy.stripe.com/fixture", ProMonthlyUSD: 6, ProYearlyUSD: 60}}
	return db, p, local, a
}

func reviewSnapshot(a *storage.Account, customer, sub, event string, version int64, plan, status string) store.BillingSnapshot {
	return store.BillingSnapshot{Provider: "stripe", CustomerID: customer, SubscriptionID: sub, AccountID: a.ID, ExpectedVersion: version, Plan: plan, EventIDs: []string{event}, ProviderReadAt: time.Now(), EvidenceSHA256: strings.Repeat("a", 64), PriceID: "price_approved", ProviderStatus: status, PaymentConfirmed: plan == "pro"}
}

func reviewReceipt(t *testing.T, local *storage.LocalStorage, customer, sub, event, typ string) {
	t.Helper()
	if _, err := local.ProcessBillingEvent(context.Background(), store.BillingEvent{Provider: "stripe", ID: event, Type: typ, CustomerID: customer, SubscriptionID: sub, Supported: true}); err != nil {
		t.Fatal(err)
	}
}

func reviewActivate(t *testing.T, local *storage.LocalStorage, a *storage.Account, customer, sub string) {
	t.Helper()
	ops, admin := local.OperationsStore(), accountOperationsAdmin(t, a.ID)
	if err := ops.BindBilling(context.Background(), admin, store.BillingMapping{Provider: "stripe", CustomerID: customer, SubscriptionID: sub, AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	reviewReceipt(t, local, customer, sub, "evt_paid_"+sub, "checkout.session.completed")
	if _, err := ops.ApplyReviewedBilling(context.Background(), admin, []store.BillingSnapshot{reviewSnapshot(a, customer, sub, "evt_paid_"+sub, 0, "pro", "active")}); err != nil {
		t.Fatal(err)
	}
}

func reviewCancel(t *testing.T, local *storage.LocalStorage, a *storage.Account, customer, sub string) {
	t.Helper()
	reviewReceipt(t, local, customer, sub, "evt_cancel_"+sub, "customer.subscription.deleted")
	if _, err := local.OperationsStore().ApplyReviewedBilling(context.Background(), accountOperationsAdmin(t, a.ID), []store.BillingSnapshot{reviewSnapshot(a, customer, sub, "evt_cancel_"+sub, 1, "free", "canceled")}); err != nil {
		t.Fatal(err)
	}
}

func TestReviewRefundCannotDowngradeActiveSubscription(t *testing.T) {
	_, p, local, a := reviewRevenueFixture(t)
	reviewActivate(t, local, a, "cus_a", "sub_a")
	body := `{"id":"evt_refund","type":"charge.refunded","data":{"object":{"id":"ch_a","customer":"cus_a","amount":600,"amount_refunded":600,"refunded":true}}}`
	refund := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix()))
	if refund.Code != 200 || !strings.Contains(refund.Body.String(), `"state":"ignored"`) {
		t.Fatal(refund.Code, refund.Body.String())
	}
	// A refund does not cancel the provider subscription. A scoped operator
	// can nevertheless revoke payment eligibility using fresh evidence.
	snap := reviewSnapshot(a, "cus_a", "sub_a", "evt_paid_sub_a", 1, "free", "active")
	_, err := local.OperationsStore().ApplyReviewedBilling(context.Background(), accountOperationsAdmin(t, a.ID), []store.BillingSnapshot{snap})
	if err != nil {
		t.Fatalf("unexpected result: %v", err)
	}
	w := revenueRequest(t, p, "/api/billing/status", true)
	if !strings.Contains(w.Body.String(), `"plan":"free"`) {
		t.Fatal(w.Body.String())
	}
}

func TestReviewResubscriptionCheckoutCannotBeFulfilled(t *testing.T) {
	_, p, local, a := reviewRevenueFixture(t)
	reviewActivate(t, local, a, "cus_a", "sub_old")
	reviewCancel(t, local, a, "cus_a", "sub_old")
	w := revenueRequest(t, p, "/upgrade", true)
	if w.Code != 409 || w.Header().Get("Location") != "" {
		t.Fatal(w.Code, w.Header())
	}
	ops, admin := local.OperationsStore(), accountOperationsAdmin(t, a.ID)
	reviewReceipt(t, local, "cus_a", "sub_new", "evt_new_paid", "checkout.session.completed")
	bindErr := ops.BindBilling(context.Background(), admin, store.BillingMapping{Provider: "stripe", CustomerID: "cus_a", SubscriptionID: "sub_new", AccountID: a.ID})
	if bindErr == nil {
		t.Fatal("new subscription was bound")
	}
	_, applyErr := ops.ApplyReviewedBilling(context.Background(), admin, []store.BillingSnapshot{reviewSnapshot(a, "cus_a", "sub_new", "evt_new_paid", 0, "pro", "active")})
	if applyErr == nil {
		t.Fatal("new paid subscription was fulfilled")
	}
	if a2, err := local.GetAccount(context.Background(), a.ID); err != nil || a2.Plan != "free" {
		t.Fatal(a2, err)
	}
}

func TestReviewCancellationRetainsPaidReservation(t *testing.T) {
	db, _, local, a := reviewRevenueFixture(t)
	reviewActivate(t, local, a, "cus_a", "sub_a")
	registration, err := local.RegisterTunnel(context.Background(), "keep-name", a.ID, "fixture")
	if err != nil || !registration.Allowed {
		t.Fatal(registration, err)
	}
	if err = local.UnregisterTunnel(context.Background(), "keep-name"); err != nil {
		t.Fatal(err)
	}
	reviewCancel(t, local, a, "cus_a", "sub_a")
	owner, err := store.NewAccountStore(db).GetSubdomainOwner("keep-name")
	if err != nil || owner != "" {
		t.Fatal(owner, err)
	}
	other, err := local.FindOrCreateByEmails(context.Background(), []string{"other@example.com"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	denied, err := local.RegisterTunnel(context.Background(), "keep-name", other.ID, "fixture")
	if err != nil || !denied.Allowed {
		t.Fatal(denied, err)
	}
	if err := local.UnregisterTunnel(context.Background(), "keep-name"); err != nil {
		t.Fatal(err)
	}
	// The new Free owner auto-reserved the reclaimed name; disconnection
	// alone cannot let the previous paid owner take it back.
	if blocked, err := local.RegisterTunnel(context.Background(), "keep-name", a.ID, "fixture"); err != nil || blocked.Allowed {
		t.Fatal(blocked, err)
	}
	if err := store.NewAccountStore(db).ReleaseSubdomain(other.ID, "keep-name"); err != nil {
		t.Fatal(err)
	}
	allowed, err := local.RegisterTunnel(context.Background(), "keep-name", a.ID, "fixture")
	if err != nil || !allowed.Allowed {
		t.Fatal(allowed, err)
	}
}

func TestReviewMergedBillingAccountsCannotCancel(t *testing.T) {
	db, p, local, a := reviewRevenueFixture(t)
	reviewActivate(t, local, a, "cus_a", "sub_a")
	b, err := local.FindOrCreateByEmails(context.Background(), []string{"alias@example.com"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	reviewActivate(t, local, b, "cus_b", "sub_b")
	merged, err := local.FindOrCreateByEmails(context.Background(), []string{a.PrimaryEmail, b.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	var mappings int
	if err = db.QueryRow(`SELECT count(*) FROM ops_billing_mappings WHERE account_id=?`, merged.ID).Scan(&mappings); err != nil || mappings != 2 {
		t.Fatal(mappings, err)
	}
	for i, binding := range []struct{ customer, sub string }{{"cus_a", "sub_a"}, {"cus_b", "sub_b"}} {
		event := fmt.Sprintf("evt_cancel_%d", i)
		reviewReceipt(t, local, binding.customer, binding.sub, event, "customer.subscription.deleted")
		_, err = local.OperationsStore().ApplyReviewedBilling(context.Background(), accountOperationsAdmin(t, merged.ID), []store.BillingSnapshot{reviewSnapshot(merged, binding.customer, binding.sub, event, 1, "free", "canceled")})
		if err != nil {
			t.Fatalf("unexpected cancellation result: %v", err)
		}
		current, err := local.GetAccount(context.Background(), merged.ID)
		want := "pro"
		if i == 1 {
			want = "free"
		}
		if err != nil || current.Plan != want {
			t.Fatalf("after cancel %d: account=%+v err=%v want=%s", i, current, err, want)
		}
	}
	w := revenueRequest(t, p, "/api/billing/status", true)
	if !strings.Contains(w.Body.String(), `"plan":"free"`) {
		t.Fatal(w.Body.String())
	}
}

func TestReviewOlderProviderReadCanOverwriteNewerCancellation(t *testing.T) {
	_, p, local, a := reviewRevenueFixture(t)
	reviewActivate(t, local, a, "cus_a", "sub_a")
	// Operator A reads the provider while active, before operator B cancels.
	// The runbook reads the provider first, then billing-status for CAS state.
	older := reviewSnapshot(a, "cus_a", "sub_a", "evt_paid_sub_a", 1, "pro", "active")
	older.ProviderReadAt = time.Now().Add(-2 * time.Minute)
	reviewCancel(t, local, a, "cus_a", "sub_a")
	ops, admin := local.OperationsStore(), accountOperationsAdmin(t, a.ID)
	status, err := ops.AdminBillingStatus(context.Background(), admin, "stripe", "sub_a")
	if err != nil || status.Mapping.Plan != "free" || status.Mapping.Version != 2 {
		t.Fatal(status, err)
	}
	older.ExpectedVersion = status.Mapping.Version
	changes, err := ops.ApplyReviewedBilling(context.Background(), admin, []store.BillingSnapshot{older})
	if err == nil {
		t.Fatalf("older evidence applied: %+v", changes)
	}
	w := revenueRequest(t, p, "/api/billing/status", true)
	if !strings.Contains(w.Body.String(), `"plan":"free"`) {
		t.Fatal(w.Body.String())
	}
}

func TestReviewPendingReceiptStillOffersSecondCheckout(t *testing.T) {
	_, p, _, _ := reviewRevenueFixture(t)
	checkout := revenueRequest(t, p, "/upgrade", true)
	if checkout.Code != 303 {
		t.Fatal(checkout.Code)
	}
	destination, err := url.Parse(checkout.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	reference := destination.Query().Get("client_reference_id")
	if reference == "" {
		t.Fatal("missing account-bound checkout reference")
	}
	body := fmt.Sprintf(`{"id":"evt_paid","type":"checkout.session.completed","data":{"object":{"id":"cs_a","customer":"cus_a","subscription":"sub_a","mode":"subscription","status":"complete","payment_status":"paid","client_reference_id":%q}}}`, reference)
	receipt := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix()))
	if receipt.Code != 200 || !strings.Contains(receipt.Body.String(), `"state":"reconciliation_required"`) {
		t.Fatal(receipt.Code, receipt.Body.String())
	}
	w := revenueRequest(t, p, "/account?billing=return", true)
	if strings.Contains(w.Body.String(), `href="/upgrade?period=monthly"`) {
		t.Fatal("return view offered checkout")
	}
	w = revenueRequest(t, p, "/account", true)
	if strings.Contains(w.Body.String(), `href="/upgrade?period=monthly"`) {
		t.Fatal("normal account view offered a second checkout")
	}
	w = revenueRequest(t, p, "/upgrade", true)
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
}

func TestReviewCheckoutDisabledDoesNotBreakFreeTunnel(t *testing.T) {
	_, p, local, a := reviewRevenueFixture(t)
	p.config.BillingEnabled = false
	w := revenueRequest(t, p, "/upgrade", true)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	for i := 0; i <= storage.FreeTunnelLimit; i++ {
		reg, err := local.RegisterTunnel(context.Background(), fmt.Sprintf("free-%d", i), a.ID, "fixture")
		if err != nil || reg.Allowed != (i < storage.FreeTunnelLimit) {
			t.Fatal(reg, err)
		}
	}
	w = httptest.NewRecorder()
	p.handlePricing(w, httptest.NewRequest("GET", "https://tunn.to/pricing", nil))
	if !strings.Contains(w.Body.String(), "5 concurrent tunnels") {
		t.Fatal(w.Body.String())
	}
}
