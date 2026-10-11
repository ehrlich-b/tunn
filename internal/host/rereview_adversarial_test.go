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
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestRereviewIssuedLinkAllowsTwoPaidSubscriptions(t *testing.T) {
	db, p, local, a := reviewRevenueFixture(t)
	redirect := revenueRequest(t, p, "/upgrade", true)
	if redirect.Code != 303 {
		t.Fatal(redirect.Code)
	}
	u, err := url.Parse(redirect.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	ref := u.Query().Get("client_reference_id")
	// Payment Links issue a new provider Session whenever the SAME URL is opened.
	// Model the resulting independently signed provider completion receipts.
	for i := 0; i < 2; i++ {
		customer, sub, event := fmt.Sprintf("cus_reuse_%d", i), fmt.Sprintf("sub_reuse_%d", i), fmt.Sprintf("evt_reuse_%d", i)
		body := fmt.Sprintf(`{"id":%q,"type":"checkout.session.completed","data":{"object":{"id":%q,"customer":%q,"subscription":%q,"mode":"subscription","payment_status":"paid","client_reference_id":%q}}}`, event, fmt.Sprintf("cs_%d", i), customer, sub, ref)
		receipt := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix()))
		if receipt.Code != 200 || !strings.Contains(receipt.Body.String(), a.ID) {
			t.Fatal(receipt.Code, receipt.Body.String())
		}
		bindErr := local.OperationsStore().BindBilling(context.Background(), accountOperationsAdmin(t, a.ID), store.BillingMapping{Provider: "stripe", CustomerID: customer, SubscriptionID: sub, AccountID: a.ID})
		_, applyErr := local.OperationsStore().ApplyReviewedBilling(context.Background(), accountOperationsAdmin(t, a.ID), []store.BillingSnapshot{reviewSnapshot(a, customer, sub, event, 0, "pro", "active")})
		if i == 0 && (bindErr != nil || applyErr != nil) {
			t.Fatal(bindErr, applyErr)
		}
		if i == 1 {
			var outcome string
			if err := db.QueryRow("SELECT outcome FROM ops_billing_events WHERE event_id=?", event).Scan(&outcome); err != nil {
				t.Fatal(err)
			}
			if bindErr == nil || applyErr == nil || outcome != "duplicate_payment_refund_needed" {
				t.Errorf("duplicate payment was not quarantined: bind=%v apply=%v outcome=%s", bindErr, applyErr, outcome)
			}
		}
	}
	var intents, subscriptions, receipts int
	db.QueryRow("SELECT count(*) FROM ops_checkout_intents").Scan(&intents)
	db.QueryRow("SELECT count(*) FROM ops_billing_states WHERE plan='pro'").Scan(&subscriptions)
	db.QueryRow("SELECT count(*) FROM ops_billing_events WHERE event_type='checkout.session.completed'").Scan(&receipts)
	t.Logf("same Stripe URL/reference: intents=%d paid_receipts=%d active_subscriptions=%d", intents, receipts, subscriptions)
	if subscriptions > 1 {
		t.Error("one issued Payment Link can produce two paid subscriptions; local checkout hold cannot prevent charging twice")
	}
	if intents != 1 || receipts != 2 || subscriptions != 1 {
		t.Errorf("lost intent/payment audit or original grant: %d/%d/%d", intents, receipts, subscriptions)
	}
}

func TestRereviewUnmarkedProductionRPCRejectsSyntheticGrant(t *testing.T) {
	db, _, local, a := reviewRevenueFixture(t)
	var markerCount int
	db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='ops_fixture'").Scan(&markerCount)
	if markerCount != 0 {
		t.Fatal("fixture marker present")
	}
	if err := local.OperationsStore().BindBilling(context.Background(), accountOperationsAdmin(t, a.ID), store.BillingMapping{Provider: "fixture", CustomerID: "cus_fake", SubscriptionID: "sub_fake", AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	event := store.BillingEvent{Provider: "fixture", ID: "evt_fake", Type: "subscription.updated", CustomerID: "cus_fake", SubscriptionID: "sub_fake", Revision: 1, Plan: "pro", Supported: true}
	data, _ := json.Marshal(event)
	server := &LoginNodeDBServer{storage: local}
	req := &internalv1.ProcessBillingEventRequest{EventJson: data}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-node-secret", "node-operator-credential"))
	response, err := nodeSecretInterceptor("node-operator-credential")(ctx, req, &grpc.UnaryServerInfo{FullMethod: "/internal.LoginNodeDB/ProcessBillingEvent"}, func(ctx context.Context, in any) (any, error) {
		return server.ProcessBillingEvent(ctx, in.(*internalv1.ProcessBillingEventRequest))
	})
	if err != nil {
		t.Log("rejected", err)
		return
	}
	got, err := local.GetAccount(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	var actor string
	db.QueryRow("SELECT actor FROM ops_billing_events WHERE event_id='evt_fake'").Scan(&actor)
	t.Logf("authenticated RPC result=%v derived_plan=%s actor=%q", response, got.Plan, actor)
	if got.Plan == "pro" {
		t.Error("production RPC accepted fixture grant without verified payment evidence or admin actor audit")
	}
}

func TestBillingDuplicatePaymentCannotUseLaterLifecycleReceipt(t *testing.T) {
	db, p, local, a := reviewRevenueFixture(t)
	redirect := revenueRequest(t, p, "/upgrade", true)
	u, err := url.Parse(redirect.Header().Get("Location"))
	if err != nil || redirect.Code != 303 {
		t.Fatal(redirect.Code, err)
	}
	ref := u.Query().Get("client_reference_id")
	for i := 0; i < 2; i++ {
		e := store.BillingEvent{Provider: "stripe", ID: fmt.Sprintf("evt_payment_%d", i), Type: "checkout.session.completed", CustomerID: fmt.Sprintf("cus_payment_%d", i), SubscriptionID: fmt.Sprintf("sub_payment_%d", i), CheckoutReference: ref, Supported: true}
		if _, err = local.ProcessBillingEvent(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	// A binding established before the completion arrived cannot evade quarantine.
	if _, err = db.Exec(`INSERT INTO ops_billing_mappings(provider,subscription_id,customer_id,account_id) VALUES('stripe','sub_payment_1','cus_payment_1',?)`, a.ID); err != nil {
		t.Fatal(err)
	}
	reviewReceipt(t, local, "cus_payment_1", "sub_payment_1", "evt_later_lifecycle", "customer.subscription.updated")
	if _, err = local.OperationsStore().ApplyReviewedBilling(context.Background(), accountOperationsAdmin(t, a.ID), []store.BillingSnapshot{reviewSnapshot(a, "cus_payment_1", "sub_payment_1", "evt_later_lifecycle", 0, "pro", "active")}); err == nil {
		t.Fatal("later receipt fulfilled duplicate subscription")
	}
	var states int
	if err = db.QueryRow(`SELECT count(*) FROM ops_billing_states`).Scan(&states); err != nil || states != 0 {
		t.Fatal(states, err)
	}
}
