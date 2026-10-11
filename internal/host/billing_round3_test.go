package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
)

// Ports of the signed HTTP and customer reproductions in REREVIEW3.md.
func TestR3EditedReferenceBypassesQuarantine(t *testing.T) {
	db, p, local, a := reviewRevenueFixture(t)
	w := revenueRequest(t, p, "/upgrade", true)
	u, _ := url.Parse(w.Header().Get("Location"))
	ref := u.Query().Get("client_reference_id")
	for i := 0; i < 2; i++ {
		reference := ref
		if i == 1 {
			reference = ""
		}
		customer, sub, event := fmt.Sprintf("cus_r3_%d", i), fmt.Sprintf("sub_r3_%d", i), fmt.Sprintf("evt_r3_%d", i)
		body := fmt.Sprintf(`{"id":%q,"type":"checkout.session.completed","data":{"object":{"id":%q,"customer":%q,"subscription":%q,"mode":"subscription","payment_status":"paid","client_reference_id":%q}}}`, event, "cs_"+sub, customer, sub, reference)
		receipt := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix()))
		if receipt.Code != 200 {
			t.Fatal(receipt.Code, receipt.Body.String())
		}
		ops, admin := local.OperationsStore(), accountOperationsAdmin(t, a.ID)
		if err := ops.BindBilling(context.Background(), admin, store.BillingMapping{Provider: "stripe", CustomerID: customer, SubscriptionID: sub, AccountID: a.ID}); err != nil {
			if i == 0 {
				t.Fatal(err)
			}
			continue
		}
		if _, err := ops.ApplyReviewedBilling(context.Background(), admin, []store.BillingSnapshot{reviewSnapshot(a, customer, sub, event, 0, "pro", "active")}); err != nil {
			t.Fatal(err)
		}
	}
	var active, quarantine int
	db.QueryRow(`SELECT count(*) FROM ops_billing_states WHERE plan='pro'`).Scan(&active)
	db.QueryRow(`SELECT count(*) FROM ops_checkout_payments WHERE outcome!='accepted'`).Scan(&quarantine)
	t.Logf("one issued intent, second signed checkout has deleted reference: active_subscriptions=%d quarantine=%d", active, quarantine)
	if active != 1 || quarantine != 1 {
		t.Errorf("edited advisory reference bypassed duplicate quarantine: active=%d quarantine=%d", active, quarantine)
	}
}

func TestR3DelayedSignedOnTimePaymentAcceptance(t *testing.T) {
	db, p, local, a := reviewRevenueFixture(t)
	w := revenueRequest(t, p, "/upgrade", true)
	u, _ := url.Parse(w.Header().Get("Location"))
	ref := u.Query().Get("client_reference_id")
	// Move intent creation into the past; paid completion occurred at +1h but
	// its FIRST delivery is now, at +25h, with a fresh valid delivery signature.
	created := time.Now().Add(-25 * time.Hour)
	if _, err := db.Exec(`UPDATE ops_checkout_intents SET created_at=? WHERE reference=?`, created.UTC().Format(time.RFC3339Nano), ref); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"id":"evt_signed_delay","created":%d,"type":"checkout.session.completed","data":{"object":{"id":"cs_signed_delay","customer":"cus_signed_delay","subscription":"sub_signed_delay","mode":"subscription","status":"complete","payment_status":"paid","client_reference_id":%q}}}`, created.Add(time.Hour).Unix(), ref)
	receipt := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix()))
	if receipt.Code != 200 {
		t.Fatal(receipt.Code, receipt.Body.String())
	}
	err := local.OperationsStore().BindBilling(context.Background(), accountOperationsAdmin(t, a.ID), store.BillingMapping{Provider: "stripe", CustomerID: "cus_signed_delay", SubscriptionID: "sub_signed_delay", AccountID: a.ID})
	if err == nil {
		_, err = local.OperationsStore().ApplyReviewedBilling(context.Background(), accountOperationsAdmin(t, a.ID), []store.BillingSnapshot{reviewSnapshot(a, "cus_signed_delay", "sub_signed_delay", "evt_signed_delay", 0, "pro", "active")})
	}
	status := revenueRequest(t, p, "/api/billing/status", true)
	t.Logf("freshly signed on-time Stripe event first delivered +25h: HTTP=%d receipt=%s binding=%v customer=%s", receipt.Code, strings.TrimSpace(receipt.Body.String()), err, strings.TrimSpace(status.Body.String()))
	if err != nil || !strings.Contains(status.Body.String(), `"plan":"pro"`) || strings.Contains(receipt.Body.String(), "checkout_expired_review_required") {
		t.Error("on-time paid completion becomes permanently unfulfillable because delivery was delayed")
	}
}

func TestR3QuarantineCustomerAndOperatorVisibility(t *testing.T) {
	db, p, local, a := reviewRevenueFixture(t)
	w := revenueRequest(t, p, "/upgrade", true)
	u, _ := url.Parse(w.Header().Get("Location"))
	ref := u.Query().Get("client_reference_id")
	for i := 0; i < 2; i++ {
		e := store.BillingEvent{Provider: "stripe", ID: fmt.Sprintf("evt_visible_%d", i), Type: "checkout.session.completed", CustomerID: fmt.Sprintf("cus_visible_%d", i), SubscriptionID: fmt.Sprintf("sub_visible_%d", i), CheckoutReference: ref, Supported: true}
		if _, err := local.ProcessBillingEvent(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	admin := accountOperationsAdmin(t, a.ID)
	if err := local.OperationsStore().BindBilling(context.Background(), admin, store.BillingMapping{Provider: "stripe", CustomerID: "cus_visible_0", SubscriptionID: "sub_visible_0", AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := local.OperationsStore().ApplyReviewedBilling(context.Background(), admin, []store.BillingSnapshot{reviewSnapshot(a, "cus_visible_0", "sub_visible_0", "evt_visible_0", 0, "pro", "active")}); err != nil {
		t.Fatal(err)
	}
	status, err := local.OperationsStore().AdminBillingStatus(context.Background(), admin, "stripe", "sub_visible_0")
	if err != nil {
		t.Fatal(err)
	}
	_, missing := local.OperationsStore().AdminBillingStatus(context.Background(), admin, "stripe", "sub_visible_1")
	account := revenueRequest(t, p, "/account?billing=return", true)
	api := revenueRequest(t, p, "/api/billing/status", true)
	var q int
	db.QueryRow(`SELECT count(*) FROM ops_checkout_payments WHERE outcome='duplicate_payment_refund_needed'`).Scan(&q)
	t.Logf("durable duplicate rows=%d; accepted-sub pending=%v; duplicate billing-status=%v; customer API=%s; customer duplicate warning=%t", q, status.PendingEventIDs, missing, strings.TrimSpace(api.Body.String()), strings.Contains(account.Body.String(), "refund"))
	if q != 1 {
		t.Fatal("missing durable quarantine")
	}
	statusJSON, _ := json.Marshal(status)
	if missing != nil || !strings.Contains(string(statusJSON), `"subscription_id":"sub_visible_1"`) {
		t.Fatal("operator cannot see unbound duplicate", status, missing)
	}
	ordinary := revenueRequest(t, p, "/account", true)
	if !strings.Contains(ordinary.Body.String(), "cancellation and refund") {
		t.Fatal("ordinary page hides duplicate")
	}
	if !strings.Contains(account.Body.String(), "refund") || !strings.Contains(api.Body.String(), "duplicate_payment_refund_needed") {
		t.Error("paid duplicate is silently represented as ordinary active Pro to its customer")
	}
}
