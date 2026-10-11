package store

import (
	"context"
	"fmt"
	"testing"
)

func TestR4BatchPreboundSubscriptionsNeedAdditionalPurchaseDecision(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	admin := operationsPrincipal(t, a.ID)
	var snaps []BillingSnapshot
	for i := 0; i < 2; i++ {
		e := BillingEvent{Provider: "stripe", ID: fmt.Sprintf("evt_r4_batch_%d", i), Type: "customer.subscription.updated", CustomerID: fmt.Sprintf("cus_r4_batch_%d", i), SubscriptionID: fmt.Sprintf("sub_r4_batch_%d", i), Supported: true}
		if err := ops.BindBilling(ctx, admin, BillingMapping{Provider: e.Provider, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID, AccountID: a.ID}); err != nil {
			t.Fatal(err)
		}
		if _, err := ops.ProcessBillingEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
		snaps = append(snaps, paymentSnapshot(ops, a, e))
	}
	result, err := ops.ApplyReviewedBilling(ctx, admin, snaps)
	var grants, decisions int
	if e := db.QueryRow(`SELECT count(*) FROM ops_billing_states WHERE provider='stripe' AND plan='pro'`).Scan(&grants); e != nil {
		t.Fatal(e)
	}
	if e := db.QueryRow(`SELECT count(*) FROM ops_payment_review_audit WHERE action='approve'`).Scan(&decisions); e != nil {
		t.Fatal(e)
	}
	notice, e := billingNotice(ctx, db, a.ID)
	if e != nil {
		t.Fatal(e)
	}
	queue, e := ops.PaymentReviewQueue(ctx, admin, "")
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("batch apply=%+v error=%v Pro subscriptions=%d additional-purchase approvals=%d notice=%q queue_items=%d", result, err, grants, decisions, notice, len(queue))
	if err == nil || grants != 0 {
		t.Error("one batch bypasses explicit additional-purchase review")
	}
	requirePlan(t, db, a.ID, "free")
	var versions, audits, reconciled int
	if e = db.QueryRow(`SELECT sum(version) FROM ops_billing_mappings`).Scan(&versions); e != nil {
		t.Fatal(e)
	}
	if e = db.QueryRow(`SELECT count(*) FROM ops_billing_events WHERE event_type='snapshot.reconciled'`).Scan(&audits); e != nil {
		t.Fatal(e)
	}
	if e = db.QueryRow(`SELECT count(*) FROM ops_billing_events WHERE outcome='reconciled'`).Scan(&reconciled); e != nil {
		t.Fatal(e)
	}
	if versions != 0 || audits != 0 || reconciled != 0 {
		t.Errorf("failed batch retained versions=%d audits=%d reconciled receipts=%d", versions, audits, reconciled)
	}
}

func TestR4BillingStatusRetainsTargetPaymentPastFirstQueuePage(t *testing.T) {
	_, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	global := operationsPrincipal(t, "*")
	admin := operationsPrincipal(t, a.ID)
	ref, err := ops.BeginBillingCheckout(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	first := BillingEvent{Provider: "stripe", ID: "evt_r4_accepted", Type: "checkout.session.completed", CustomerID: "cus_r4_accepted", SubscriptionID: "sub_r4_accepted", SessionID: "cs_r4_accepted", CheckoutReference: ref, Supported: true}
	if _, err = ops.ProcessBillingEvent(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err = ops.BindBilling(ctx, admin, BillingMapping{Provider: first.Provider, CustomerID: first.CustomerID, SubscriptionID: first.SubscriptionID, AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{paymentSnapshot(ops, a, first)}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 101; i++ {
		e := BillingEvent{Provider: "stripe", ID: fmt.Sprintf("evt_r4_q_%03d", i), Type: "checkout.session.completed", CustomerID: fmt.Sprintf("cus_r4_q_%03d", i), SubscriptionID: fmt.Sprintf("sub_r4_q_%03d", i), SessionID: fmt.Sprintf("cs_r4_q_%03d", i), Supported: true}
		if _, err := ops.ProcessBillingEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
		if i == 100 {
			if err := ops.BindBilling(ctx, operationsPrincipal(t, a.ID), BillingMapping{Provider: e.Provider, SubscriptionID: e.SubscriptionID, CustomerID: e.CustomerID, AccountID: a.ID}); err == nil {
				t.Fatal("unowned binding bypassed review")
			}
		}
	}
	page, err := ops.PaymentReviewQueue(ctx, global, "")
	if err != nil || len(page) != 100 {
		t.Fatal(page, err)
	}
	last := page[len(page)-1]
	next, err := ops.PaymentReviewQueue(ctx, global, last.Provider+"/"+last.SubscriptionID)
	if err != nil || len(next) != 1 {
		t.Fatal("pagination", next, err)
	}
	status, err := ops.AdminBillingStatus(ctx, global, "stripe", "sub_r4_q_100")
	if err != nil {
		t.Fatal(err)
	}
	acceptedStatus, err := ops.AdminBillingStatus(ctx, global, "stripe", first.SubscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("target outcome=%s accepted subscription status payments=%+v", next[0].Outcome, acceptedStatus.Payments)
	t.Logf("queue pages=%d/%d target=%s target status payments=%+v", len(page), len(next), next[0].SubscriptionID, status.Payments)
	if len(status.Payments) != 1 || status.Payments[0].SubscriptionID != next[0].SubscriptionID {
		t.Error("direct status silently omits its own target payment after global queue first page")
	}
	if len(acceptedStatus.Payments) != 1 || acceptedStatus.Payments[0].SubscriptionID != next[0].SubscriptionID {
		t.Error("accepted subscription status silently omits its account's duplicate payment")
	}
}
