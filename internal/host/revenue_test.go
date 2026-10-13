package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func revenueFixture(t *testing.T) (*ProxyServer, *storage.LocalStorage, *storage.Account) {
	t.Helper()
	local := securityDB(t)
	a, err := local.FindOrCreateByEmails(context.Background(), []string{"owner+demo@example.com"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	p := &ProxyServer{Domain: "tunn.to", storage: local, config: &config.Config{Environment: config.EnvProd, Domain: "tunn.to", JWTSecret: "fixture-revenue-signing-key", BillingEnabled: true, StripeWebhookSecret: "whsec_fixture", StripeCheckoutURLMonthly: "https://buy.stripe.com/fixture?locale=en", ProMonthlyUSD: 5, ProYearlyUSD: 48}}
	return p, local, a
}

func revenueRequest(t *testing.T, p *ProxyServer, path string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "https://tunn.to"+path, nil)
	if auth {
		r.AddCookie(&http.Cookie{Name: "tunn_auth", Value: relayJWT(t, p, "owner+demo@example.com")})
	}
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}

func TestRevenueRoutesLimitsAndConfiguredCheckout(t *testing.T) {
	p, _, a := revenueFixture(t)
	for _, path := range []string{"/", "/pricing", "/docs", "/docs/mcp-to-claude", "/ngrok-alternative", "/terms"} {
		w := revenueRequest(t, p, path, false)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	w := revenueRequest(t, p, "/pricing", false)
	for _, want := range []string{"$5/month", "$48", "1000000", "10000000", "10.0 GB", "500.0 GB", "<strong>5</strong>", "<strong>25</strong>", "<strong>1</strong>", "<strong>10</strong>", "No automatic overage charges", "Billed monthly", "/upgrade?period=monthly"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Error("missing pricing fact", want)
		}
	}
	if strings.Contains(w.Body.String(), "href=\"/upgrade?period=yearly\"") {
		t.Fatal("unconfigured annual checkout advertised")
	}
	if w := revenueRequest(t, p, "/does-not-exist", false); w.Code != 404 {
		t.Fatal("unknown route is homepage", w.Code)
	}
	if w := revenueRequest(t, p, "/upgrade?period=monthly", false); w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "return_to=%2Fupgrade%3Fperiod%3Dmonthly") {
		t.Fatal("lost upgrade login intent", w.Code, w.Header())
	}
	w = revenueRequest(t, p, "/upgrade?period=monthly", true)
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != 303 || u.Host != "buy.stripe.com" || u.Query().Get("prefilled_email") != a.PrimaryEmail || u.Query().Get("client_reference_id") == "" || u.Query().Get("client_reference_id") == a.ID || u.Query().Get("locale") != "en" {
		t.Fatal(w.Code, u, err)
	}
	p.config.ProMonthlyUSD = 8
	p.config.OwnerMonthlyBytes = 500000000
	p.config.OwnerMonthlyRequests = 4000
	w = revenueRequest(t, p, "/pricing", false)
	for _, want := range []string{"$8/month", "500.0 MB", "4000"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Error("config not reflected", want)
		}
	}
}

func TestRevenueCheckoutMissingUnsafeDisabledOrAccountUnavailable(t *testing.T) {
	for _, raw := range []string{"", "#", "http://buy.stripe.com/a", "https://attacker.example/pay", "https://buy.stripe.com@attacker.example/pay", "https://buy.stripe.com:444/pay", "https://buy.stripe.com/pay#bad"} {
		p, _, _ := revenueFixture(t)
		p.config.StripeCheckoutURLMonthly = raw
		if w := revenueRequest(t, p, "/upgrade", true); w.Code != 503 {
			t.Fatal(raw, w.Code, w.Header())
		}
		w := revenueRequest(t, p, "/account", true)
		if strings.Contains(w.Body.String(), `href="#"`) {
			t.Fatal("no-op checkout exposed")
		}
	}
	p, _, _ := revenueFixture(t)
	p.config.BillingEnabled = false
	if w := revenueRequest(t, p, "/upgrade", true); w.Code != 503 {
		t.Fatal(w.Code)
	}
	p.config.BillingEnabled = true
	p.config.StripeWebhookSecret = ""
	if w := revenueRequest(t, p, "/upgrade", true); w.Code != 503 {
		t.Fatal("billing without signed receipts", w.Code)
	}
	p.storage = storage.NewProxyStorage()
	for _, path := range []string{"/upgrade", "/account", "/api/billing/status"} {
		if w := revenueRequest(t, p, path, true); w.Code != 503 {
			t.Fatal("outage mislabeled as Free", path, w.Code)
		}
	}
}

func TestRevenuePaymentReturnReadsCommittedEntitlement(t *testing.T) {
	p, local, a := revenueFixture(t)
	ctx := context.Background()
	w := revenueRequest(t, p, "/account?billing=return&plan=pro&session_id=cs_forged", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Pro activation is pending") || strings.Contains(w.Body.String(), `href="/upgrade?period=`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := revenueRequest(t, p, "/api/billing/status?plan=pro&paid=true", true); !strings.Contains(w.Body.String(), `"state":"pending"`) {
		t.Fatal(w.Body.String())
	}
	ops := local.OperationsStore()
	admin := accountOperationsAdmin(t, a.ID)
	if err := ops.BindBilling(ctx, admin, store.BillingMapping{Provider: "stripe", CustomerID: "cus_revenue", SubscriptionID: "sub_revenue", AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := local.ProcessBillingEvent(ctx, store.BillingEvent{Provider: "stripe", ID: "evt_revenue", Type: "checkout.session.completed", CustomerID: "cus_revenue", SubscriptionID: "sub_revenue", Supported: true}); err != nil {
		t.Fatal(err)
	}
	if w := revenueRequest(t, p, "/api/billing/status", true); !strings.Contains(w.Body.String(), `"plan":"free"`) {
		t.Fatal("receipt granted Pro", w.Body.String())
	}
	snap := store.BillingSnapshot{Provider: "stripe", CustomerID: "cus_revenue", SubscriptionID: "sub_revenue", AccountID: a.ID, Plan: "pro", EventIDs: []string{"evt_revenue"}, ProviderReadAt: time.Now(), EvidenceSHA256: strings.Repeat("d", 64), PriceID: "price_approved", ProviderStatus: "active", PaymentConfirmed: true}
	if _, err := ops.ApplyReviewedBilling(ctx, admin, []store.BillingSnapshot{snap}); err != nil {
		t.Fatal(err)
	}
	w = revenueRequest(t, p, "/api/billing/status", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"active"`) || w.Result().Header.Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String(), w.Header())
	}
	if w := revenueRequest(t, p, "/upgrade", true); w.Code != 303 || w.Header().Get("Location") != "/account" {
		t.Fatal("Pro repurchase offered", w.Code, w.Header())
	}
	if _, err := ops.Transition(ctx, admin, a.ID, "suspended", "review hold", 0); err != nil {
		t.Fatal(err)
	}
	if w := revenueRequest(t, p, "/api/billing/status", true); !strings.Contains(w.Body.String(), `"state":"suspended"`) {
		t.Fatal(w.Body.String())
	}
	if w := revenueRequest(t, p, "/upgrade", true); w.Code != 403 {
		t.Fatal("suspended account checkout", w.Code)
	}
}

func TestRevenueRoutesProtectPlatformHostAndTunnelOwnership(t *testing.T) {
	p, _, _ := revenueFixture(t)
	for _, path := range []string{"/upgrade", "/api/billing/status"} {
		r := httptest.NewRequest("GET", "https://foreign.example"+path, nil)
		r.AddCookie(&http.Cookie{Name: "tunn_auth", Value: relayJWT(t, p, "owner+demo@example.com")})
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 403 && w.Code != 404 {
			t.Fatal("foreign host accepted", path, w.Code)
		}
		r = httptest.NewRequest("POST", "https://tunn.to"+path, nil)
		w = httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 405 {
			t.Fatal(path, w.Code)
		}
	}
	// Tunnel origins still receive publisher traffic, including /pricing.
	p.tunnelServer = NewTunnelServer(p.config, nil, nil, p.storage)
	r := httptest.NewRequest("GET", "https://offline.tunn.to/pricing", nil)
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code == 200 || strings.Contains(w.Body.String(), "Simple pricing") {
		t.Fatal("platform page on publisher origin", w.Code, w.Body.String())
	}
}

func TestRevenueOwnerQuotaIncludesUpgradeHint(t *testing.T) {
	w := httptest.NewRecorder()
	setMeterHeaders(w, &pb.Decision{Reason: "owner_byte_budget", Status: 429})
	if w.Header().Get("Tunn-Upgrade-URL") != "https://tunn.to/pricing" || w.Header().Get("Tunn-Limit-Reason") != "owner_byte_budget" {
		t.Fatal(w.Header())
	}
	w = httptest.NewRecorder()
	setMeterHeaders(w, &pb.Decision{Reason: "request_rate", Status: 429})
	if w.Header().Get("Tunn-Upgrade-URL") != "" {
		t.Fatal("consumer grant limit marketed as owner upgrade")
	}
}

func TestPricingReflectsStoredPlan(t *testing.T) {
	p, local, account := revenueFixture(t)
	if err := local.UpdatePlan(context.Background(), account.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	w := revenueRequest(t, p, "/pricing", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Current plan") || !strings.Contains(w.Body.String(), "View usage") || strings.Contains(w.Body.String(), `href="/upgrade?`) || w.Result().Header.Get("Cache-Control") != "no-store" {
		t.Fatal("stored plan not reflected in pricing", w.Code)
	}
	visitor := revenueRequest(t, p, "/pricing?plan=pro", false)
	if strings.Contains(visitor.Body.String(), "Current plan") || !strings.Contains(visitor.Body.String(), "Start free") {
		t.Fatal("query string granted a plan")
	}
}
