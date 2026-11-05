package host

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
)

type autoStripeTransport func(*http.Request) (*http.Response, error)

func (f autoStripeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type autoStripeStorage struct {
	*storage.LocalStorage
	automation *store.StripeAutomation
}

func (s autoStripeStorage) ProcessBillingEvent(ctx context.Context, e store.BillingEvent) (*store.BillingResult, error) {
	return s.automation.Process(ctx, s.OperationsStore(), e)
}

func TestAutoActivationSignedWebhookAndAuthorityBoundary(t *testing.T) {
	p, db := stripeCorrectnessFixture(t)
	local := p.storage.(*storage.LocalStorage)
	account, err := local.AccountStore().FindOrCreateByEmails([]string{"paid@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = local.OperationsStore().BindBilling(context.Background(), accountOperationsAdmin(t, account.ID), store.BillingMapping{Provider: "stripe", CustomerID: "cus_signed", SubscriptionID: "sub_signed", AccountID: account.ID}); err != nil {
		t.Fatal(err)
	}
	reads := 0
	now := time.Now().Unix()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		if r.URL.Path != "/v1/subscriptions/sub_signed" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		fmt.Fprintf(w, `{"id":"sub_signed","customer":"cus_signed","status":"active","current_period_start":%d,"current_period_end":%d,"items":{"data":[{"price":{"id":"price_signed"}}]},"latest_invoice":{"id":"in_signed","customer":"cus_signed","subscription":"sub_signed","status":"paid","paid":true,"amount_paid":2000,"amount_remaining":0,"charge":{"id":"ch_signed","customer":"cus_signed","invoice":"in_signed","paid":true},"lines":{"data":[{"type":"subscription","subscription":"sub_signed","price":{"id":"price_signed"},"period":{"start":%d,"end":%d}}]}}}`, now-10, now+3600, now-10, now+3600)
	}))
	defer provider.Close()
	transport := autoStripeTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.stripe.com" {
			t.Fatalf("unexpected destination %s", r.URL.Host)
		}
		clone := r.Clone(r.Context())
		u := *r.URL
		clone.URL = &u
		clone.URL.Scheme = "http"
		clone.URL.Host = strings.TrimPrefix(provider.URL, "http://")
		return provider.Client().Transport.RoundTrip(clone)
	})
	automation := store.NewStripeAutomation("sk_test_signed", []string{"price_signed"}, transport)
	p.storage = autoStripeStorage{local, automation}
	p.config.StripeWebhookSecret = "whsec_signed"
	// The body's status is deliberately false. Only the provider GET can grant.
	body := `{"id":"evt_signed","type":"customer.subscription.created","data":{"object":{"id":"sub_signed","customer":"cus_signed","status":"canceled"}}}`
	invalid := stripeFixtureRequest(p, body, "t=1,v1=bad")
	if invalid.Code != 400 || reads != 0 {
		t.Fatal(invalid.Code, reads)
	}
	for i := 0; i < 2; i++ {
		response := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix()))
		if response.Code != 200 {
			t.Fatal(response.Code, response.Body.String())
		}
		var result store.BillingResult
		if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.State != "reconciled" || result.Duplicate != (i == 1) {
			t.Fatal(result, err)
		}
	}
	a, err := local.AccountStore().GetByID(account.ID)
	if err != nil || a.Plan != "pro" || reads != 1 {
		t.Fatal(a, err, reads)
	}
	var audits int
	if err = db.QueryRow(`SELECT count(*) FROM ops_billing_events WHERE actor='system:stripe'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal(audits, err)
	}
	// Authenticated node intake cannot smuggle payment confirmation or a Price.
	// The real LocalStorage entrypoint ignores invented JSON fields and retrieves
	// evidence itself when enabled; disabled configuration leaves it pending.
	server := NewLoginNodeDBServer(local)
	rpc := []byte(`{"provider":"stripe","id":"evt_rpc","type":"customer.subscription.updated","customer_id":"cus_signed","subscription_id":"sub_signed","supported":true,"plan":"pro","payment_confirmed":true,"price_id":"price_signed"}`)
	result, err := server.ProcessBillingEvent(context.Background(), &internalv1.ProcessBillingEventRequest{EventJson: rpc})
	if err != nil {
		t.Fatal(err)
	}
	var out store.BillingResult
	if err = json.Unmarshal(result.ResultJson, &out); err != nil || out.State != "reconciliation_required" {
		t.Fatal(out, err)
	}
}
func TestAutoActivationRefundNormalization(t *testing.T) {
	for _, tc := range []struct{ typ, body string }{
		{"charge.refunded", `{"id":"ch_refund"}`},
		{"charge.dispute.created", `{"id":"dp_refund","charge":"ch_refund"}`},
	} {
		e, err := normalizeStripeEvent(StripeEvent{ID: "evt_refund", Type: tc.typ, Data: StripeEventData{Object: json.RawMessage(tc.body)}}, []byte(tc.body))
		if err != nil || !e.Supported || e.ChargeID != "ch_refund" || e.SubscriptionID != "" {
			t.Fatal(e, err)
		}
	}
}

// Exercise the buyer path without pre-binding or supplied reconciliation truth.
// Every case gets a new on-disk database and an entirely local provider.
func TestStripeFirstCustomerCheckoutToConsumer(t *testing.T) {
	for _, period := range []string{"monthly", "yearly"} {
		for _, scenario := range []string{"paid", "wrong_customer", "wrong_price", "unpaid", "failed_invoice", "unknown_response", "refund", "cancellation"} {
			t.Run(period+"/"+scenario, func(t *testing.T) {
				p, db := stripeCorrectnessFixture(t)
				local := p.storage.(*storage.LocalStorage)
				p.Domain, p.config.Domain = "tunn.to", "tunn.to"
				p.config.BillingEnabled = true
				p.config.StripeWebhookSecret = "whsec_first_fixture"
				p.config.StripeCheckoutURLMonthly = "https://buy.stripe.com/monthly_fixture"
				p.config.StripeCheckoutURLYearly = "https://buy.stripe.com/yearly_fixture"
				owner, err := local.FindOrCreateByEmails(context.Background(), []string{"owner+demo@example.com"}, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				other, err := local.FindOrCreateByEmails(context.Background(), []string{"other@example.invalid"}, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				duration := int64(30 * 24 * 3600)
				if period == "yearly" {
					duration = 365 * 24 * 3600
				}
				price := "price_" + period
				customer, currentPrice, status, invoiceStatus := "cus_first", price, "active", "paid"
				paid, unknown, refunded, scheduled := true, false, false, false
				var start, end int64
				reads := 0
				transport := autoStripeTransport(func(r *http.Request) (*http.Response, error) {
					reads++
					if r.Method != "GET" || r.URL.Host != "api.stripe.com" || r.Header.Get("Stripe-Version") != "2024-06-20" {
						t.Fatalf("unexpected provider request: %s %s", r.Method, r.URL)
					}
					if r.URL.Path == "/v1/charges/ch_first" {
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"ch_first","customer":"cus_first","invoice":"in_first"}`)), Header: make(http.Header)}, nil
					}
					if r.URL.Path == "/v1/invoices/in_first" {
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"customer":"cus_first","subscription":"sub_first"}`)), Header: make(http.Header)}, nil
					}
					if r.URL.Path != "/v1/subscriptions/sub_first" {
						t.Fatalf("unexpected provider path: %s", r.URL.Path)
					}
					body := fmt.Sprintf(`{"id":"sub_first","customer":%q,"status":%q,"cancel_at_period_end":%t,"current_period_start":%d,"current_period_end":%d,"items":{"data":[{"price":{"id":%q}}]},"latest_invoice":{"id":"in_first","customer":%q,"subscription":"sub_first","status":%q,"paid":%t,"amount_paid":500,"amount_remaining":0,"charge":{"id":"ch_first","customer":%q,"invoice":"in_first","paid":true,"amount_refunded":%d},"lines":{"data":[{"type":"subscription","subscription":"sub_first","price":{"id":%q},"period":{"start":%d,"end":%d}}]}}}`, customer, status, scheduled, start, end, currentPrice, customer, invoiceStatus, paid, customer, map[bool]int{true: 500}[refunded], currentPrice, start, end)
					if unknown {
						body = `{"unexpected":"unknown provider shape"}`
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
				})
				p.storage = autoStripeStorage{local, store.NewStripeAutomation("sk_test_fixture", []string{price}, transport)}
				checkout := revenueRequest(t, p, "/upgrade?period="+period, true)
				u, err := url.Parse(checkout.Header().Get("Location"))
				if err != nil || checkout.Code != 303 || u.Path != "/"+period+"_fixture" {
					t.Fatal(checkout.Code, u, err)
				}
				reference := u.Query().Get("client_reference_id")
				if reference == "" || reference == owner.ID {
					t.Fatal("missing opaque intent")
				}
				// The completion follows the committed intent, even if the host
				// wall clock changes between checkout and this fixture event.
				var created string
				if err := db.QueryRow(`SELECT created_at FROM ops_checkout_intents WHERE reference=?`, reference).Scan(&created); err != nil {
					t.Fatal(err)
				}
				issued, err := time.Parse(time.RFC3339Nano, created)
				if err != nil {
					t.Fatal(err)
				}
				now := issued.Unix()
				start, end = now-10, now+duration
				send := func(id, typ string, completion bool) store.BillingResult {
					t.Helper()
					object := `{"id":"sub_first","customer":"cus_first","status":"active","metadata":{"account_id":"` + other.ID + `"}}`
					if completion {
						object = fmt.Sprintf(`{"id":"cs_first","customer":"cus_first","subscription":"sub_first","mode":"subscription","payment_status":"paid","client_reference_id":%q,"metadata":{"account_id":%q}}`, reference, other.ID)
					}
					if typ == "invoice.paid" {
						object = `{"id":"in_first","customer":"cus_first","subscription":"sub_first"}`
					}
					if typ == "charge.refunded" {
						object = `{"id":"ch_first"}`
					}
					body := fmt.Sprintf(`{"id":%q,"created":%d,"type":%q,"data":{"object":%s}}`, id, now, typ, object)
					w := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix()))
					var result store.BillingResult
					if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
						t.Fatal(w.Code, w.Body.String())
					}
					return result
				}
				check := func(plan string, mappings, audits int) {
					t.Helper()
					api := revenueRequest(t, p, "/api/billing/status?paid=true&plan=pro", true)
					var output struct{ Plan, State string }
					if api.Code != 200 || json.Unmarshal(api.Body.Bytes(), &output) != nil || output.Plan != plan {
						t.Fatal(api.Code, api.Body.String(), plan)
					}
					wantState := "pending"
					if plan == "pro" {
						wantState = "active"
					}
					if output.State != wantState {
						t.Fatal(output)
					}
					page := revenueRequest(t, p, "/account?billing=return", true)
					if page.Code != 200 || plan == "free" && !strings.Contains(page.Body.String(), "Pro activation is pending") {
						t.Fatal(page.Code, page.Body.String())
					}
					account, e := local.GetAccount(context.Background(), other.ID)
					if e != nil || account.Plan != "free" {
						t.Fatal("metadata transferred ownership", account, e)
					}
					var n, a int
					if e = db.QueryRow(`SELECT (SELECT count(*) FROM ops_billing_mappings WHERE account_id=?),(SELECT count(*) FROM ops_billing_events WHERE actor='system:stripe')`, owner.ID).Scan(&n, &a); e != nil || n != mappings || a != audits {
						t.Fatal(n, a, e)
					}
					t.Logf("consumer plan=%s state=%s owner mappings=%d automatic audits=%d", output.Plan, output.State, n, a)
				}
				// Notification before the ownership receipt cannot grant.
				send("evt_early", "customer.subscription.updated", false)
				check("free", 0, 0)
				switch scenario {
				case "wrong_customer":
					customer = "cus_other"
				case "wrong_price":
					currentPrice = "price_unknown"
				case "unpaid":
					paid = false
				case "failed_invoice":
					invoiceStatus = "open"
				case "unknown_response":
					unknown = true
				}
				first := send("evt_checkout", "checkout.session.completed", true)
				negative := scenario != "paid" && scenario != "refund" && scenario != "cancellation"
				if negative {
					if first.State != "reconciliation_required" {
						t.Fatal(first)
					}
					check("free", 0, 0)
					// A delayed invoice/provider recovery retries the SAME durable receipt.
					customer, currentPrice, paid, invoiceStatus, unknown = "cus_first", price, true, "paid", false
					first = send("evt_checkout", "checkout.session.completed", true)
				}
				if first.State != "reconciled" || first.AccountID != owner.ID {
					t.Fatal(first)
				}
				check("pro", 1, 1)
				before := reads
				if replay := send("evt_checkout", "checkout.session.completed", true); !replay.Duplicate || reads != before {
					t.Fatal("duplicate re-read or lost deduplication", replay, reads, before)
				}
				assertReceipt := func(id, outcome, account string) {
					t.Helper()
					var gotOutcome, gotAccount, sub, cust string
					err := db.QueryRow(`SELECT outcome,account_id,subscription_id,customer_id FROM ops_billing_events WHERE provider='stripe' AND event_id=?`, id).Scan(&gotOutcome, &gotAccount, &sub, &cust)
					if err != nil || gotOutcome != outcome || gotAccount != account || sub != "sub_first" || cust != "cus_first" {
						t.Fatal(id, gotOutcome, gotAccount, sub, cust, err)
					}
				}
				paid = false
				before = reads
				pending := send("evt_delayed_renewal", "invoice.paid", false)
				if pending.State != "reconciliation_required" || reads != before+1 {
					t.Fatal(pending, reads, before)
				}
				assertReceipt("evt_delayed_renewal", "reconciliation_required", owner.ID)
				check("pro", 1, 1) // Ambiguous payment preserves the prior entitlement.
				paid = true
				before = reads
				recovered := send("evt_delayed_renewal", "invoice.paid", false)
				if recovered.State != "reconciled" || recovered.AccountID != owner.ID || reads != before+1 {
					t.Fatal(recovered, reads, before)
				}
				assertReceipt("evt_delayed_renewal", "reconciled", owner.ID)
				var oldDigest, newDigest, statePlan string
				if err := db.QueryRow(`SELECT digest FROM ops_billing_states WHERE provider='stripe' AND subscription_id='sub_first'`).Scan(&oldDigest); err != nil {
					t.Fatal(err)
				}
				// A new paid renewal period commits a new state without another grant.
				start, end = now-1, now+duration+3600
				before = reads
				renewed := send("evt_renewal", "invoice.paid", false)
				if renewed.State != "reconciled" || renewed.AccountID != owner.ID || reads != before+1 {
					t.Fatal(renewed, reads, before)
				}
				assertReceipt("evt_renewal", "reconciled", owner.ID)
				if err := db.QueryRow(`SELECT digest,plan FROM ops_billing_states WHERE provider='stripe' AND subscription_id='sub_first'`).Scan(&newDigest, &statePlan); err != nil || newDigest == oldDigest || statePlan != "pro" {
					t.Fatal(oldDigest, newDigest, statePlan, err)
				}
				check("pro", 1, 1)
				scheduled = true
				send("evt_scheduled", "customer.subscription.updated", false)
				check("pro", 1, 1)
				if scenario == "refund" || scenario == "cancellation" {
					if scenario == "refund" {
						refunded = true
					} else {
						status = "canceled"
					}
					typ := "customer.subscription.deleted"
					if scenario == "refund" {
						typ = "charge.refunded"
					}
					send("evt_revoke", typ, false)
					check("free", 1, 2)
					send("evt_checkout", "checkout.session.completed", true)
					send("evt_old_active", "customer.subscription.created", false)
					check("free", 1, 2)
					if w := revenueRequest(t, p, "/upgrade", true); w.Code != 409 {
						t.Fatal("returning purchase must require support", w.Code)
					}
				}
			})
		}
	}
}
