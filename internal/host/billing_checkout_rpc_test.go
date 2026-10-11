package host

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBillingCheckoutProxyPreservesAuthorityState(t *testing.T) {
	p, local, a := revenueFixture(t)
	p.storage = securityReplicaStorage(t, local)
	checkout := revenueRequest(t, p, "/upgrade", true)
	u, err := url.Parse(checkout.Header().Get("Location"))
	if err != nil || checkout.Code != 303 || u.Query().Get("client_reference_id") == "" {
		t.Fatal(checkout.Code, u, err)
	}
	reference := u.Query().Get("client_reference_id")
	p.config.StripeCheckoutURLYearly = "https://buy.stripe.com/changed-yearly"
	if resumed := revenueRequest(t, p, "/upgrade?period=yearly", true); resumed.Code != 303 || resumed.Header().Get("Location") != checkout.Header().Get("Location") {
		t.Fatal("replica changed unpaid intent/destination", resumed.Code, resumed.Header())
	}
	body := fmt.Sprintf(`{"id":"evt_proxy_paid","type":"checkout.session.completed","data":{"object":{"customer":"cus_proxy","subscription":"sub_proxy","mode":"subscription","client_reference_id":%q}}}`, reference)
	receipt := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix()))
	if receipt.Code != 200 || !strings.Contains(receipt.Body.String(), a.ID) {
		t.Fatal(receipt.Code, receipt.Body.String())
	}
	if w := revenueRequest(t, p, "/upgrade", true); w.Code != 409 {
		t.Fatal("replica offered duplicate checkout", w.Code)
	}
	if w := revenueRequest(t, p, "/account", true); strings.Contains(w.Body.String(), `href="/upgrade?period=`) || !strings.Contains(w.Body.String(), "Pro activation is pending") {
		t.Fatal(w.Body.String())
	}
	reviewActivate(t, local, a, "cus_proxy", "sub_proxy")
	if current, err := p.storage.GetAccount(context.Background(), a.ID); err != nil || current.Plan != "pro" || current.BillingState != "active" {
		t.Fatal(current, err)
	}
	reviewCancel(t, local, a, "cus_proxy", "sub_proxy")
	if current, err := p.storage.GetAccount(context.Background(), a.ID); err != nil || current.Plan != "free" || current.BillingState != "support" {
		t.Fatal(current, err)
	}
	if w := revenueRequest(t, p, "/upgrade", true); w.Code != 409 {
		t.Fatal("replica offered unfulfillable resubscription", w.Code)
	}
}

func TestBillingCheckoutDashboardOffersUnpaidResume(t *testing.T) {
	_, p, _, _ := reviewRevenueFixture(t)
	first := revenueRequest(t, p, "/upgrade", true)
	if first.Code != 303 {
		t.Fatal(first.Code)
	}
	if page := revenueRequest(t, p, "/account", true); page.Code != 200 || !strings.Contains(page.Body.String(), `href="/upgrade">Resume checkout`) || strings.Contains(page.Body.String(), `href="/upgrade?period=`) {
		t.Fatal("dashboard lost unpaid resume or offered new purchase", page.Code, page.Body.String())
	}
	p.config.StripeCheckoutURLMonthly = "https://buy.stripe.com/changed-monthly"
	if resumed := revenueRequest(t, p, "/upgrade", true); resumed.Code != 303 || resumed.Header().Get("Location") != first.Header().Get("Location") {
		t.Fatal("retry changed durable destination", resumed.Code, resumed.Header())
	}
}

func TestBillingCheckoutRequiresDurableIntent(t *testing.T) {
	db, p, local, a := reviewRevenueFixture(t)
	if _, err := db.Exec(`CREATE TRIGGER fail_intent BEFORE INSERT ON ops_checkout_intents BEGIN SELECT RAISE(ABORT,'intent storage failure'); END`); err != nil {
		t.Fatal(err)
	}
	if w := revenueRequest(t, p, "/upgrade", true); w.Code != 503 || w.Header().Get("Location") != "" {
		t.Fatal("uncommitted intent exposed Payment Link", w.Code, w.Header())
	}
	if current, err := local.GetAccount(context.Background(), a.ID); err != nil || current.BillingState != "available" {
		t.Fatal(current, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_intent`); err != nil {
		t.Fatal(err)
	}
	if w := revenueRequest(t, p, "/upgrade", true); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if current, err := local.GetAccount(context.Background(), a.ID); err != nil || current.BillingState != "resumable" || current.Plan != "free" {
		t.Fatal(current, err)
	}
}
