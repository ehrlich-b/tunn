package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
