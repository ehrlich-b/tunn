package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func paymentDecision(ops *OperationsStore, a *Account, e BillingEvent) PaymentReview {
	return PaymentReview{Provider: e.Provider, SubscriptionID: e.SubscriptionID, CustomerID: e.CustomerID, SessionID: e.SessionID, EventID: e.ID, AccountID: a.ID, Action: "approve", Reason: "verified provider payment and ownership", ProviderReadAt: ops.now(), EvidenceSHA256: strings.Repeat("c", 64)}
}
func paymentSnapshot(ops *OperationsStore, a *Account, e BillingEvent) BillingSnapshot {
	return BillingSnapshot{Provider: e.Provider, SubscriptionID: e.SubscriptionID, CustomerID: e.CustomerID, AccountID: a.ID, Plan: "pro", ProviderStatus: "active", PaymentConfirmed: true, EventIDs: []string{e.ID}, ProviderReadAt: ops.now(), EvidenceSHA256: strings.Repeat("a", 64), PriceID: "price_reviewed"}
}

// Port of the store delayed-delivery reproducer, with completion evidence now
// retained separately from intake time. Also cover real post-window purchases.
func TestR3LatePaymentAndDeliveryReviews(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "delayed", true: "actually-late"}[late], func(t *testing.T) {
			db, ops, a, _ := operationsFixture(t)
			ctx := context.Background()
			admin := operationsPrincipal(t, a.ID)
			ref, _, err := ops.PrepareBillingCheckout(ctx, a.ID, "https://buy.stripe.com/r3")
			if err != nil {
				t.Fatal(err)
			}
			issued := ops.now()
			ops.now = func() time.Time { return issued.Add(25 * time.Hour) }
			completed := issued.Add(time.Hour)
			if late {
				completed = issued.Add(25 * time.Hour)
			}
			e := BillingEvent{Provider: "stripe", ID: "evt_delay", Type: "checkout.session.completed", SessionID: "cs_delay", CustomerID: "cus_delay", SubscriptionID: "sub_delay", CheckoutReference: ref, CompletedAt: completed.Unix(), Supported: true}
			if _, err = ops.ProcessBillingEvent(ctx, e); err != nil {
				t.Fatal(err)
			}
			if late {
				if err = ops.BindBilling(ctx, admin, BillingMapping{Provider: e.Provider, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID, AccountID: a.ID}); err == nil {
					t.Fatal("late payment bypassed review")
				}
				d := paymentDecision(ops, a, e)
				if err = ops.ReviewCheckoutPayment(ctx, operationsPrincipal(t, "other"), d); !errors.Is(err, ErrDenied) {
					t.Fatal("scope bypass", err)
				}
				if _, err = db.Exec(`CREATE TRIGGER fail_payment_audit BEFORE INSERT ON ops_payment_review_audit BEGIN SELECT RAISE(ABORT,'audit failure'); END`); err != nil {
					t.Fatal(err)
				}
				if err = ops.ReviewCheckoutPayment(ctx, admin, d); err == nil {
					t.Fatal("unaudited approval committed")
				}
				if _, err = db.Exec(`DROP TRIGGER fail_payment_audit`); err != nil {
					t.Fatal(err)
				}
				if err = ops.ReviewCheckoutPayment(ctx, admin, d); err != nil {
					t.Fatal(err)
				}
				requirePlan(t, db, a.ID, "free") // review alone never grants
				if err = ops.ReviewCheckoutPayment(ctx, admin, d); !errors.Is(err, ErrVersionConflict) {
					t.Fatal("CAS replay", err)
				}
			}
			if err = ops.BindBilling(ctx, admin, BillingMapping{Provider: e.Provider, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID, AccountID: a.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err = ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{paymentSnapshot(ops, a, e)}); err != nil {
				t.Fatal(err)
			}
			requirePlan(t, db, a.ID, "pro")
		})
	}
}

func TestR3MissingUnknownReferencesAndRefundResolution(t *testing.T) {
	for _, ref := range []string{"", "unknown-edited-reference"} {
		t.Run(ref, func(t *testing.T) {
			db, ops, a, path := operationsFixture(t)
			ctx := context.Background()
			admin := operationsPrincipal(t, a.ID)
			first := BillingEvent{Provider: "stripe", ID: "evt_first", Type: "checkout.session.completed", SessionID: "cs_first", CustomerID: "cus_first", SubscriptionID: "sub_first", Supported: true}
			if err := ops.BindBilling(ctx, admin, BillingMapping{Provider: first.Provider, CustomerID: first.CustomerID, SubscriptionID: first.SubscriptionID, AccountID: a.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err := ops.ProcessBillingEvent(ctx, first); err != nil {
				t.Fatal(err)
			}
			if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{paymentSnapshot(ops, a, first)}); err != nil {
				t.Fatal(err)
			}
			second := BillingEvent{Provider: "stripe", ID: "evt_second", Type: "checkout.session.completed", SessionID: "cs_second", CustomerID: "cus_second", SubscriptionID: "sub_second", Supported: true, CheckoutReference: ref}
			if _, err := ops.ProcessBillingEvent(ctx, second); err != nil {
				t.Fatal(err)
			}
			global := operationsPrincipal(t, "*")
			all, err := ops.PaymentReviewQueue(ctx, global, "")
			if err != nil || len(all) != 1 || all[0].SessionID != second.SessionID {
				t.Fatal(all, err)
			}
			scoped, err := ops.PaymentReviewQueue(ctx, admin, "")
			if err != nil || len(scoped) != 0 {
				t.Fatal("unowned receipt leaked", scoped, err)
			}
			if err = ops.BindBilling(ctx, admin, BillingMapping{Provider: second.Provider, CustomerID: second.CustomerID, SubscriptionID: second.SubscriptionID, AccountID: a.ID}); err == nil {
				t.Fatal("second purchase bound")
			}
			all, err = ops.PaymentReviewQueue(ctx, admin, "")
			if err != nil || len(all) != 1 || all[0].Outcome != "duplicate_payment_refund_needed" {
				t.Fatal(all, err)
			}
			// A lifecycle receipt must not bypass quarantine.
			lifecycle := second
			lifecycle.ID = "evt_lifecycle"
			lifecycle.Type = "customer.subscription.updated"
			if _, err = ops.ProcessBillingEvent(ctx, lifecycle); err != nil {
				t.Fatal(err)
			}
			if _, err = ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{paymentSnapshot(ops, a, lifecycle)}); err == nil {
				t.Fatal("lifecycle bypass")
			}
			d := paymentDecision(ops, a, second)
			d.ExpectedVersion = all[0].Version
			if err = ops.ReviewCheckoutPayment(ctx, admin, d); err == nil {
				t.Fatal("additional purchase approved without decision")
			}
			d.Action = "refunded"
			d.RefundID = "re_second"
			d.CancellationID = "provider-canceled-sub_second"
			if err = ops.ReviewCheckoutPayment(ctx, admin, d); err != nil {
				t.Fatal(err)
			}
			requirePlan(t, db, a.ID, "pro")
			if notice, err := billingNotice(ctx, db, a.ID); err != nil || notice != "" {
				t.Fatal(notice, err)
			}
			if all, err = ops.PaymentReviewQueue(ctx, global, ""); err != nil || len(all) != 0 {
				t.Fatal(all, err)
			}
			if err = ops.BindBilling(ctx, admin, BillingMapping{Provider: second.Provider, CustomerID: second.CustomerID, SubscriptionID: second.SubscriptionID, AccountID: a.ID}); err == nil {
				t.Fatal("refunded subscription rebound")
			}
			db.Close()
			db, err = OpenLocal(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			ops = NewOperationsStore(db, ops.now)
			if _, err = ops.ProcessBillingEvent(ctx, second); err != nil {
				t.Fatal("resolved replay lost", err)
			}
			requirePlan(t, db, a.ID, "pro")
			var resolution, outcome string
			if err = db.QueryRow(`SELECT resolution,outcome FROM ops_checkout_payments WHERE subscription_id=?`, second.SubscriptionID).Scan(&resolution, &outcome); err != nil || resolution != "refunded" || outcome != "duplicate_payment_refund_needed" {
				t.Fatal("evidence erased", resolution, outcome, err)
			}
		})
	}
}

func TestR3ApproveUnownedFirstPaymentAndLegitimateAdditionalPurchase(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	admin := operationsPrincipal(t, a.ID)
	for i, e := range []BillingEvent{
		{Provider: "stripe", ID: "evt_unowned", Type: "checkout.session.completed", SessionID: "cs_unowned", CustomerID: "cus_unowned", SubscriptionID: "sub_unowned", Supported: true},
		{Provider: "stripe", ID: "evt_legitimate", Type: "checkout.session.completed", SessionID: "cs_legitimate", CustomerID: "cus_legitimate", SubscriptionID: "sub_legitimate", Supported: true},
	} {
		if _, err := ops.ProcessBillingEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
		d := paymentDecision(ops, a, e)
		if i == 0 {
			if err := ops.BindBilling(ctx, admin, BillingMapping{Provider: e.Provider, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID, AccountID: a.ID}); err == nil {
				t.Fatal("unowned payment bypassed review")
			}
			queue, err := ops.PaymentReviewQueue(ctx, admin, "")
			if err != nil || len(queue) != 1 {
				t.Fatal(queue, err)
			}
			d.ExpectedVersion = queue[0].Version
			if _, _, err := ops.PrepareBillingCheckout(ctx, a.ID, "https://buy.stripe.com/new"); !errors.Is(err, ErrCheckoutBlocked) {
				t.Fatal("claimed unowned payment sold another checkout", err)
			}
		}
		d.AllowAdditional = i > 0
		d.Reason = "ownership verified; distinct legitimate merged purchase reviewed"
		if err := ops.ReviewCheckoutPayment(ctx, admin, d); err != nil {
			t.Fatal(err)
		}
		if err := ops.BindBilling(ctx, admin, BillingMapping{Provider: e.Provider, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID, AccountID: a.ID}); err != nil {
			t.Fatal(err)
		}
		if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{paymentSnapshot(ops, a, e)}); err != nil {
			t.Fatal(err)
		}
	}
	requirePlan(t, db, a.ID, "pro")
}

func TestR3ApprovalCannotReviveAnOlderVerifiedSnapshot(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	admin := operationsPrincipal(t, a.ID)
	first := BillingEvent{Provider: "stripe", ID: "evt_prior", Type: "customer.subscription.updated", CustomerID: "cus_prior", SubscriptionID: "sub_prior", Supported: true}
	if err := ops.BindBilling(ctx, admin, BillingMapping{Provider: first.Provider, CustomerID: first.CustomerID, SubscriptionID: first.SubscriptionID, AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ProcessBillingEvent(ctx, first); err != nil {
		t.Fatal(err)
	}
	snap := paymentSnapshot(ops, a, first)
	if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{snap}); err != nil {
		t.Fatal(err)
	}
	// A recognized expired completion quarantines an already reviewed grant.
	if _, err := db.Exec(`INSERT INTO ops_checkout_intents VALUES('r3-expired',?,?)`, a.ID, ops.now().Add(-25*time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	completion := first
	completion.ID = "evt_completion"
	completion.Type = "checkout.session.completed"
	completion.SessionID = "cs_completion"
	completion.CheckoutReference = "r3-expired"
	if _, err := ops.ProcessBillingEvent(ctx, completion); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "free")
	now := ops.now().Add(time.Minute)
	ops.now = func() time.Time { return now }
	if err := ops.ReviewCheckoutPayment(ctx, admin, paymentDecision(ops, a, completion)); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "free")
	snap.ExpectedVersion = 1
	if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{snap}); err == nil {
		t.Fatal("pre-approval evidence restored Pro")
	}
	snap.ProviderReadAt = ops.now()
	snap.EventIDs = []string{completion.ID}
	if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{snap}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "pro")
}

func TestR3PreboundFreeStateCannotBypassAdditionalPurchaseDecision(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	admin := operationsPrincipal(t, a.ID)
	events := []BillingEvent{
		{Provider: "stripe", ID: "evt_prebound_a", Type: "customer.subscription.updated", CustomerID: "cus_prebound_a", SubscriptionID: "sub_prebound_a", Supported: true},
		{Provider: "stripe", ID: "evt_prebound_b", Type: "customer.subscription.updated", CustomerID: "cus_prebound_b", SubscriptionID: "sub_prebound_b", Supported: true},
	}
	for _, e := range events {
		if err := ops.BindBilling(ctx, admin, BillingMapping{Provider: e.Provider, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID, AccountID: a.ID}); err != nil {
			t.Fatal(err)
		}
		if _, err := ops.ProcessBillingEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{paymentSnapshot(ops, a, events[0])}); err != nil {
		t.Fatal(err)
	}
	snap := paymentSnapshot(ops, a, events[1])
	snap.Plan = "free"
	snap.PaymentConfirmed = false
	if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{snap}); err != nil {
		t.Fatal(err)
	}
	now := ops.now().Add(time.Second)
	ops.now = func() time.Time { return now }
	snap.Plan = "pro"
	snap.PaymentConfirmed = true
	snap.ExpectedVersion = 1
	snap.ProviderReadAt = now
	if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{snap}); err == nil {
		t.Fatal("Free review substituted for explicit additional-purchase decision")
	}
	requirePlan(t, db, a.ID, "pro")
	var grants int
	if err := db.QueryRow(`SELECT count(*) FROM ops_billing_states WHERE plan='pro'`).Scan(&grants); err != nil || grants != 1 {
		t.Fatal(grants, err)
	}
}
