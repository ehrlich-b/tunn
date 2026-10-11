package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestReviewedStripeBillingActivationCancellationAndCAS(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	p := operationsPrincipal(t, a.ID)
	mapping := BillingMapping{Provider: "stripe", CustomerID: "cus_review", SubscriptionID: "sub_review", AccountID: a.ID}
	if err := ops.BindBilling(ctx, p, mapping); err != nil {
		t.Fatal(err)
	}
	event := BillingEvent{Provider: "stripe", ID: "evt_paid", Type: "checkout.session.completed", CustomerID: mapping.CustomerID, SubscriptionID: mapping.SubscriptionID, Supported: true}
	if _, err := ops.ProcessBillingEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	snap := BillingSnapshot{Provider: "stripe", CustomerID: mapping.CustomerID, SubscriptionID: mapping.SubscriptionID, AccountID: a.ID, Plan: "pro", EventIDs: []string{event.ID}, ProviderReadAt: ops.now(), EvidenceSHA256: strings.Repeat("a", 64), PriceID: "price_approved", ProviderStatus: "active", PaymentConfirmed: true}
	changes, err := ops.Reconcile(ctx, p, []BillingSnapshot{snap}, false)
	if err != nil || changes[0].State != "change_expected" {
		t.Fatal(changes, err)
	}
	requirePlan(t, db, a.ID, "free")
	for _, mutate := range []func(*BillingSnapshot){
		func(s *BillingSnapshot) { s.ProviderReadAt = ops.now().Add(-6 * time.Minute) },
		func(s *BillingSnapshot) { s.ProviderReadAt = ops.now().Add(time.Minute) },
		func(s *BillingSnapshot) { s.EvidenceSHA256 = "" },
		func(s *BillingSnapshot) { s.PaymentConfirmed = false },
		func(s *BillingSnapshot) { s.PriceID = "" },
		func(s *BillingSnapshot) { s.ProviderStatus = "trialing" },
		func(s *BillingSnapshot) { s.EventIDs = nil },
		func(s *BillingSnapshot) { s.EventIDs = []string{"evt_unknown"} },
		func(s *BillingSnapshot) { s.Revision = 123 },
	} {
		bad := snap
		mutate(&bad)
		if _, err = ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{bad}); err == nil {
			t.Fatal("invalid review applied", bad)
		}
		requirePlan(t, db, a.ID, "free")
	}
	if _, err = ops.ApplyReviewedBilling(ctx, operationsPrincipal(t, "other"), []BillingSnapshot{snap}); err == nil {
		t.Fatal("unscoped operator applied")
	}
	if _, err = ops.Transition(ctx, p, a.ID, "suspended", "review hold", 0); err != nil {
		t.Fatal(err)
	}
	changes, err = ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{snap})
	if err != nil || changes[0].State != "applied" {
		t.Fatal(changes, err)
	}
	requirePlan(t, db, a.ID, "pro")
	state, err := ops.LookupAccountStatus(ctx, a.ID)
	if err != nil || state.State != "suspended" {
		t.Fatal("billing cleared suspension", state, err)
	}
	if _, err = ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{snap}); err == nil {
		t.Fatal("stale version replay applied")
	}
	status, err := ops.AdminBillingStatus(ctx, p, "stripe", "sub_review")
	if err != nil || status.Mapping.Version != 1 || len(status.PendingEventIDs) != 0 {
		t.Fatal(status, err)
	}
	var actor, digest string
	if err = db.QueryRow(`SELECT actor,digest FROM ops_billing_events WHERE event_type='snapshot.reconciled'`).Scan(&actor, &digest); err != nil || actor != "fixture-operator" || len(digest) != 64 {
		t.Fatal(actor, digest, err)
	}
	event.ID, event.Type = "evt_cancel", "customer.subscription.deleted"
	if _, err = ops.ProcessBillingEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	cancelTime := ops.now().Add(time.Second)
	ops.now = func() time.Time { return cancelTime }
	snap.ProviderReadAt = cancelTime
	snap.ExpectedVersion, snap.Plan, snap.ProviderStatus, snap.EventIDs = 1, "free", "canceled", []string{event.ID}
	changes, err = ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{snap})
	if err != nil || changes[0].State != "applied" {
		t.Fatal(changes, err)
	}
	requirePlan(t, db, a.ID, "free")
	// Reordered old provider events are still receipts and cannot grant Pro.
	event.ID, event.Type = "evt_late", "customer.subscription.updated"
	if _, err = ops.ProcessBillingEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "free")
}

func TestReviewedStripeBillingBatchFailsAtomically(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	p := operationsPrincipal(t, a.ID)
	if err := ops.BindBilling(ctx, p, BillingMapping{Provider: "stripe", CustomerID: "cus_batch", SubscriptionID: "sub_batch", AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ProcessBillingEvent(ctx, BillingEvent{Provider: "stripe", ID: "evt_batch", Type: "customer.subscription.updated", CustomerID: "cus_batch", SubscriptionID: "sub_batch", Supported: true}); err != nil {
		t.Fatal(err)
	}
	snap := BillingSnapshot{Provider: "stripe", CustomerID: "cus_batch", SubscriptionID: "sub_batch", AccountID: a.ID, Plan: "pro", EventIDs: []string{"evt_batch"}, ProviderReadAt: ops.now(), EvidenceSHA256: strings.Repeat("b", 64), PriceID: "price_approved", ProviderStatus: "active", PaymentConfirmed: true}
	bad := snap
	bad.SubscriptionID = "sub_unbound"
	if _, err := ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{snap, bad}); err == nil {
		t.Fatal("invalid batch applied")
	}
	requirePlan(t, db, a.ID, "free")
}
