package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBillingLegacyReconciliationRequiresGlobalAuthorityAndAudit(t *testing.T) {
	path := seedLegacy110485c(t)
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	ops := NewOperationsStore(db, nil)
	var id string
	if err = db.QueryRow(`SELECT id FROM accounts WHERE primary_email='operator@example.invalid'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	decision := LegacyEntitlementDecision{OriginalAccountID: id, AccountID: id, Plan: "free", Reason: "explicit global grant review"}
	plans, names := rereviewRows(t, db, `SELECT id,plan FROM accounts`), rereviewRows(t, db, `SELECT subdomain,account_id FROM reserved_subdomains`)
	for _, principal := range []AdminPrincipal{AdminPrincipal{}, operationsPrincipal(t, id)} {
		if err = ops.ReconcileLegacyEntitlements(ctx, principal, []LegacyEntitlementDecision{decision}); !errors.Is(err, ErrDenied) {
			t.Fatal("scoped legacy cutover accepted", err)
		}
	}
	global := operationsPrincipal(t, "*")
	bad := decision
	bad.OriginalAccountID = "nonexistent"
	if err = ops.ReconcileLegacyEntitlements(ctx, global, []LegacyEntitlementDecision{decision, bad}); err == nil {
		t.Fatal("invalid batch applied")
	}
	if _, err = db.Exec(`CREATE TRIGGER fail_legacy_audit BEFORE INSERT ON ops_legacy_entitlement_audit BEGIN SELECT RAISE(ABORT,'audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = ops.ReconcileLegacyEntitlements(ctx, global, []LegacyEntitlementDecision{decision}); err == nil {
		t.Fatal("audit failure accepted")
	}
	if !reflect.DeepEqual(plans, rereviewRows(t, db, `SELECT id,plan FROM accounts`)) || !reflect.DeepEqual(names, rereviewRows(t, db, `SELECT subdomain,account_id FROM reserved_subdomains`)) {
		t.Fatal("failed/global-denied batch changed entitlement or names")
	}
	requirePlan(t, db, id, "pro")
	var audits int
	if err = db.QueryRow(`SELECT count(*) FROM ops_legacy_entitlement_audit`).Scan(&audits); err != nil || audits != 0 {
		t.Fatal("failed batch retained an audit", audits, err)
	}
	if _, err = db.Exec(`DROP TRIGGER fail_legacy_audit`); err != nil {
		t.Fatal(err)
	}
	if err = ops.ReconcileLegacyEntitlements(ctx, global, []LegacyEntitlementDecision{decision}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, id, "free")
	var actor, reason, previous, plan string
	if err = db.QueryRow(`SELECT actor,reason,previous_plan,plan FROM ops_legacy_entitlement_audit`).Scan(&actor, &reason, &previous, &plan); err != nil || actor != "fixture-operator" || reason != decision.Reason || previous != "pro" || plan != "free" {
		t.Fatal(actor, reason, previous, plan, err)
	}
	if err = ops.ReconcileLegacyEntitlements(ctx, global, []LegacyEntitlementDecision{decision}); !errors.Is(err, ErrVersionConflict) {
		t.Fatal("stale legacy decision accepted", err)
	}
	if err = MigrateOperations(db); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, id, "free")
	var reservations int
	if err = db.QueryRow(`SELECT count(*) FROM reserved_subdomains`).Scan(&reservations); err != nil || reservations != 5 {
		t.Fatal("cutover changed other accounts", reservations, err)
	}
	status, err := ops.LookupAccountStatus(ctx, id)
	if err != nil || status.State != "suspended" {
		t.Fatal("legacy review cleared suspension", status, err)
	}
}

func TestBillingLegacyGrantSurvivesScopedCancellationAndMerge(t *testing.T) {
	db, err := OpenLocal(seedLegacy110485c(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	ops, accounts := NewOperationsStore(db, nil), NewAccountStore(db)
	a, err := accounts.GetByEmail("stripe-paid@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	e := BillingEvent{Provider: "stripe", ID: "evt_cancel_legacy", Type: "customer.subscription.deleted", CustomerID: "cus_paid", SubscriptionID: "sub_paid", Supported: true}
	if _, err = ops.ProcessBillingEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	snap := BillingSnapshot{Provider: "stripe", AccountID: a.ID, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID, Plan: "free", EventIDs: []string{e.ID}, ProviderReadAt: time.Now(), EvidenceSHA256: strings.Repeat("a", 64), PriceID: "price_reviewed", ProviderStatus: "canceled"}
	if _, err = ops.ApplyReviewedBilling(ctx, operationsPrincipal(t, a.ID), []BillingSnapshot{snap}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "pro")
	if owner, err := accounts.GetSubdomainOwner("legacy-stripe-paid"); err != nil || owner != a.ID {
		t.Fatal("scoped billing review ended legacy grant", owner, err)
	}
	b, err := accounts.GetByEmail("manual@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github")
	if err != nil || merged.Plan != "pro" {
		t.Fatal(merged, err)
	}
	global := operationsPrincipal(t, "*")
	for i, original := range []string{a.ID, b.ID} {
		if err = ops.ReconcileLegacyEntitlements(ctx, global, []LegacyEntitlementDecision{{OriginalAccountID: original, AccountID: merged.ID, Plan: "free", Reason: "global merged grant review"}}); err != nil {
			t.Fatal(err)
		}
		want := "pro"
		if i == 1 {
			want = "free"
		}
		requirePlan(t, db, merged.ID, want)
		for _, name := range []string{"legacy-stripe-paid", "legacy-manual"} {
			owner, err := accounts.GetSubdomainOwner(name)
			if err != nil || i == 0 && owner != merged.ID || i == 1 && owner != "" {
				t.Fatal("merged grant/name ownership lost", owner, err)
			}
		}
	}
}

func TestBillingCheckoutResumesDestinationAndExpiresWithoutReplacement(t *testing.T) {
	db, ops, a, path := operationsFixture(t)
	ctx := context.Background()
	first := "https://buy.stripe.com/monthly?locale=en"
	ref, dest, err := ops.PrepareBillingCheckout(ctx, a.ID, first)
	if err != nil || dest != first {
		t.Fatal(ref, dest, err)
	}
	clock := ops.now()
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ops = NewOperationsStore(db, func() time.Time { return clock })
	resumed, saved, err := ops.PrepareBillingCheckout(ctx, a.ID, "https://buy.stripe.com/yearly")
	if err != nil || resumed != ref || saved != first {
		t.Fatal("destination changed after restart", resumed, saved, err)
	}
	clock = clock.Add(CheckoutResumeWindow)
	if _, _, err = ops.PrepareBillingCheckout(ctx, a.ID, first); !errors.Is(err, ErrCheckoutBlocked) {
		t.Fatal("expired intent reopened checkout", err)
	}
	var intents int
	if err = db.QueryRow(`SELECT count(*) FROM ops_checkout_intents`).Scan(&intents); err != nil || intents != 1 {
		t.Fatal(intents, err)
	}
	e := BillingEvent{Provider: "stripe", ID: "evt_late_paid", Type: "checkout.session.completed", CustomerID: "cus_late", SubscriptionID: "sub_late", CheckoutReference: ref, Supported: true}
	r, err := ops.ProcessBillingEvent(ctx, e)
	if err != nil || r.State != "checkout_expired_review_required" || r.AccountID != a.ID {
		t.Fatal("late payment lost or granted", r, err)
	}
	if err = ops.BindBilling(ctx, operationsPrincipal(t, a.ID), BillingMapping{Provider: "stripe", AccountID: a.ID, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID}); err == nil {
		t.Fatal("expired payment bound")
	}
	requirePlan(t, db, a.ID, "free")
}

func TestBillingCheckoutConcurrentCompletionsConsumeOnceAndPersist(t *testing.T) {
	db, ops, a, path := operationsFixture(t)
	ctx := context.Background()
	ref, err := ops.BeginBillingCheckout(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	const completions = 12
	var wg sync.WaitGroup
	for i := 0; i < completions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := ops.ProcessBillingEvent(ctx, BillingEvent{Provider: "stripe", ID: fmt.Sprintf("evt_concurrent_%d", i), Type: "checkout.session.completed", CustomerID: fmt.Sprintf("cus_%d", i), SubscriptionID: fmt.Sprintf("sub_%d", i), CheckoutReference: ref, Supported: true})
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var accepted, duplicates, receipts int
	if err = db.QueryRow(`SELECT count(*) FROM ops_checkout_payments WHERE outcome='accepted'`).Scan(&accepted); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM ops_checkout_payments WHERE outcome='duplicate_payment_refund_needed'`).Scan(&duplicates); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM ops_billing_events`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if accepted != 1 || duplicates != completions-1 || receipts != completions {
		t.Fatal("completion ledger lost or double-consumed", accepted, duplicates, receipts)
	}
	ops = NewOperationsStore(db, ops.now)
	if _, err = ops.BeginBillingCheckout(ctx, a.ID); !errors.Is(err, ErrCheckoutBlocked) {
		t.Fatal("paid intent resumed", err)
	}
}

func TestBillingCheckoutReceiptFailureDoesNotConsumeIntent(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	ref, err := ops.BeginBillingCheckout(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER fail_checkout_receipt BEFORE INSERT ON ops_billing_events BEGIN SELECT RAISE(ABORT,'receipt failure'); END`); err != nil {
		t.Fatal(err)
	}
	e := BillingEvent{Provider: "stripe", ID: "evt_failure", Type: "checkout.session.completed", CustomerID: "cus_failure", SubscriptionID: "sub_failure", CheckoutReference: ref, Supported: true}
	if _, err = ops.ProcessBillingEvent(ctx, e); err == nil {
		t.Fatal("failed receipt accepted")
	}
	var payments int
	if err = db.QueryRow(`SELECT count(*) FROM ops_checkout_payments`).Scan(&payments); err != nil || payments != 0 {
		t.Fatal("failed receipt consumed intent", payments, err)
	}
	if _, err = db.Exec(`DROP TRIGGER fail_checkout_receipt`); err != nil {
		t.Fatal(err)
	}
	result, err := ops.ProcessBillingEvent(ctx, e)
	if err != nil || result.State != "reconciliation_required" {
		t.Fatal(result, err)
	}
}
