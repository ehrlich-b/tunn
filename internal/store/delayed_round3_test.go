package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Port of the store reproduction in r3_store_test.go. Encode completion
// evidence as metadata so this identical body also compiles at 4416eff, where
// normalization loses that timestamp and the safety assertion fails.
func TestR3DelayedOnTimeCompletionCanBeFulfilled(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	issued := ops.now()
	ref, _, err := ops.PrepareBillingCheckout(ctx, a.ID, "https://buy.stripe.com/r3")
	if err != nil {
		t.Fatal(err)
	}
	ops.now = func() time.Time { return issued.Add(25 * time.Hour) }
	data, err := json.Marshal(map[string]any{"provider": "stripe", "id": "evt_delay_store", "type": "checkout.session.completed", "customer_id": "cus_delay_store", "subscription_id": "sub_delay_store", "checkout_reference": ref, "session_id": "cs_delay_store", "completed_at": issued.Add(time.Hour).Unix(), "supported": true})
	if err != nil {
		t.Fatal(err)
	}
	var e BillingEvent
	if err = json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	result, err := ops.ProcessBillingEvent(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	admin := operationsPrincipal(t, a.ID)
	err = ops.BindBilling(ctx, admin, BillingMapping{Provider: e.Provider, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID, AccountID: a.ID})
	if err != nil {
		t.Fatalf("on-time payment first delivered at +25h cannot be fulfilled: %s: %v", result.State, err)
	}
	snap := BillingSnapshot{Provider: e.Provider, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID, AccountID: a.ID, Plan: "pro", ProviderStatus: "active", PaymentConfirmed: true, EventIDs: []string{e.ID}, ProviderReadAt: ops.now(), EvidenceSHA256: strings.Repeat("a", 64), PriceID: "price_delay"}
	if _, err = ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{snap}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "pro")
}
