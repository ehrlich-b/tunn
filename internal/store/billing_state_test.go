package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func orderedStripeFixture(t *testing.T) (*OperationsStore, BillingSnapshot, string) {
	t.Helper()
	db, ops, a, path := operationsFixture(t)
	ctx := context.Background()
	p := operationsPrincipal(t, a.ID)
	if err := ops.BindBilling(ctx, p, BillingMapping{Provider: "stripe", CustomerID: "cus_ordered", SubscriptionID: "sub_ordered", AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ProcessBillingEvent(ctx, BillingEvent{Provider: "stripe", ID: "evt_ordered", Type: "customer.subscription.updated", CustomerID: "cus_ordered", SubscriptionID: "sub_ordered", Supported: true}); err != nil {
		t.Fatal(err)
	}
	snap := BillingSnapshot{Provider: "stripe", CustomerID: "cus_ordered", SubscriptionID: "sub_ordered", AccountID: a.ID, Plan: "pro", ProviderStatus: "active", PaymentConfirmed: true, ProviderReadAt: ops.now().Add(-time.Minute), PriceID: "price_ordered", EvidenceSHA256: strings.Repeat("e", 64), EventIDs: []string{"evt_ordered"}}
	if _, err := ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{snap}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "pro")
	snap.ExpectedVersion = 1
	return ops, snap, path
}

func TestBillingReviewedWatermarkReplayTiesAndRestart(t *testing.T) {
	ops, snap, path := orderedStripeFixture(t)
	ctx := context.Background()
	p := operationsPrincipal(t, snap.AccountID)
	// A replay with current CAS is a no-op and cannot grow versions or audits.
	if out, err := ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{snap}); err != nil || out[0].State != "current" {
		t.Fatal(out, err)
	}
	conflicting := snap
	conflicting.Plan, conflicting.PaymentConfirmed = "free", false
	if _, err := ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{conflicting}); err == nil {
		t.Fatal("equal-time conflicting eligibility accepted")
	}
	// Fresh evidence of unchanged state still advances the review watermark.
	snap.ProviderReadAt = snap.ProviderReadAt.Add(time.Second)
	if out, err := ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{snap}); err != nil || out[0].State != "applied" {
		t.Fatal(out, err)
	}
	snap.ExpectedVersion = 2
	if err := ops.db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ops = NewOperationsStore(db, ops.now)
	conflicting.ExpectedVersion = 2
	if _, err := ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{conflicting}); err == nil {
		t.Fatal("restart forgot newer unchanged-state review")
	}
	snap.ProviderReadAt = snap.ProviderReadAt.Add(time.Second)
	snap.Plan, snap.PaymentConfirmed = "free", false
	if _, err := ops.ApplyReviewedBilling(ctx, p, []BillingSnapshot{snap}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, snap.AccountID, "free")
	// Reconciled receipt replay cannot restore the old state.
	if r, err := ops.ProcessBillingEvent(ctx, BillingEvent{Provider: "stripe", ID: "evt_ordered", Type: "customer.subscription.updated", CustomerID: "cus_ordered", SubscriptionID: "sub_ordered", Supported: true}); err != nil || !r.Duplicate || r.State != "reconciled" {
		t.Fatal(r, err)
	}
	requirePlan(t, db, snap.AccountID, "free")
	var version, audits int
	if err = db.QueryRow(`SELECT version FROM ops_billing_mappings`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM ops_billing_events WHERE event_type='snapshot.reconciled'`).Scan(&audits); err != nil || version != 3 || audits != 3 {
		t.Fatal(version, audits, err)
	}
}

func TestBillingDowngradeRollsBackReservationsAndVerifiedState(t *testing.T) {
	ops, snap, _ := orderedStripeFixture(t)
	a := NewAccountStore(ops.db)
	if err := a.ReserveSubdomain(snap.AccountID, "atomic-name"); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.db.Exec(`CREATE TRIGGER fail_release BEFORE DELETE ON reserved_subdomains BEGIN SELECT RAISE(ABORT,'release failure'); END`); err != nil {
		t.Fatal(err)
	}
	snap.Plan, snap.PaymentConfirmed = "free", false
	snap.ProviderReadAt = snap.ProviderReadAt.Add(time.Second)
	if _, err := ops.ApplyReviewedBilling(context.Background(), operationsPrincipal(t, snap.AccountID), []BillingSnapshot{snap}); err == nil {
		t.Fatal("failed reservation release committed")
	}
	requirePlan(t, ops.db, snap.AccountID, "pro")
	if owner, err := a.GetSubdomainOwner("atomic-name"); err != nil || owner != snap.AccountID {
		t.Fatal(owner, err)
	}
	state, err := ops.AdminBillingStatus(context.Background(), operationsPrincipal(t, snap.AccountID), "stripe", "sub_ordered")
	if err != nil || state.Mapping.Version != 1 || !state.Mapping.ProviderReadAt.Equal(snap.ProviderReadAt.Add(-time.Second)) {
		t.Fatal(state, err)
	}
	if _, err = ops.db.Exec(`DROP TRIGGER fail_release`); err != nil {
		t.Fatal(err)
	}
	if _, err = ops.ApplyReviewedBilling(context.Background(), operationsPrincipal(t, snap.AccountID), []BillingSnapshot{snap}); err != nil {
		t.Fatal(err)
	}
	if owner, err := a.GetSubdomainOwner("atomic-name"); err != nil || owner != "" {
		t.Fatal(owner, err)
	}
}

func TestBillingCheckoutConcurrencyMergeAndRestart(t *testing.T) {
	db, ops, a, path := operationsFixture(t)
	ctx := context.Background()
	const attempts = 12
	start := make(chan struct{})
	refs := make(chan string, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			reference, err := ops.BeginBillingCheckout(ctx, a.ID)
			if err != nil && !errors.Is(err, ErrCheckoutBlocked) {
				t.Error(err)
			}
			refs <- reference
		}()
	}
	close(start)
	wg.Wait()
	close(refs)
	winners := 0
	var reference string
	for ref := range refs {
		if ref != "" {
			winners++
			if reference != "" && ref != reference {
				t.Fatal("concurrent resume created another intent", reference, ref)
			}
			reference = ref
		}
	}
	if winners != attempts || reference == a.ID {
		t.Fatal(winners, reference)
	}
	var intents int
	if err := db.QueryRow("SELECT count(*) FROM ops_checkout_intents").Scan(&intents); err != nil || intents != 1 {
		t.Fatal(intents, err)
	}
	accounts := NewAccountStore(db)
	b, err := accounts.FindOrCreateByEmails([]string{"pending-alias@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ops.BeginBillingCheckout(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github")
	if err != nil || merged.BillingState != "resumable" || merged.Plan != "free" {
		t.Fatal(merged, err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ops = NewOperationsStore(db, ops.now)
	if _, err = ops.BeginBillingCheckout(ctx, a.ID); !errors.Is(err, ErrCheckoutBlocked) {
		t.Fatal(err)
	}
	result, err := ops.ProcessBillingEvent(ctx, BillingEvent{Provider: "stripe", ID: "evt_intent", Type: "checkout.session.completed", CustomerID: "cus_intent", SubscriptionID: "sub_intent", Supported: true, CheckoutReference: reference})
	if err != nil || result.AccountID != merged.ID || result.State != "reconciliation_required" {
		t.Fatal(result, err)
	}
	forged := BillingEvent{Provider: "stripe", ID: "evt_forged", Type: "checkout.session.completed", CustomerID: "cus_forged", SubscriptionID: "sub_forged", Supported: true, CheckoutReference: merged.ID}
	if result, err = ops.ProcessBillingEvent(ctx, forged); err != nil || result.AccountID != "" {
		t.Fatal("editable account UUID trusted", result, err)
	}
	requirePlan(t, db, merged.ID, "free")
}

func TestBillingMissingVerifiedStateFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unverified.db")
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accounts := NewAccountStore(db)
	a, err := accounts.FindOrCreateByEmails([]string{"unverified@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.UpdatePlan(a.ID, "pro"); err == nil {
		t.Fatal("direct production plan grant accepted")
	}
	// Simulate corruption in a new-code projection, not an old-code grant
	// request. Preserve this test's unjournaled-cache/no-import assertions;
	// journaled old writes and quota cache repair have separate R3 coverage.
	if _, err = db.Exec(`INSERT INTO ops_projection_guard VALUES(?); UPDATE accounts SET plan='pro' WHERE id=?; DELETE FROM ops_projection_guard WHERE account_id=?`, a.ID, a.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "free")
	ops := NewOperationsStore(db, nil)
	if err = ops.BindBilling(context.Background(), operationsPrincipal(t, a.ID), BillingMapping{Provider: "stripe", CustomerID: "cus_unknown", SubscriptionID: "sub_unknown", AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	// One verified identity may own separate provider customers, including
	// purchases made before their pending accounts merged. Binding remains
	// per customer/subscription and confers no eligibility by itself.
	if err = ops.BindBilling(context.Background(), operationsPrincipal(t, a.ID), BillingMapping{Provider: "stripe", CustomerID: "cus_other", SubscriptionID: "sub_other", AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "free")
	if err = ops.BindBilling(context.Background(), operationsPrincipal(t, a.ID), BillingMapping{Provider: "stripe", CustomerID: "cus_unknown", SubscriptionID: "sub_replacement", AccountID: a.ID}); err == nil {
		t.Fatal("customer replacement bypassed binding protection")
	}

	if _, err = db.Exec(`INSERT INTO ops_projection_guard VALUES(?); UPDATE ops_billing_mappings SET plan='pro'; UPDATE accounts SET plan='pro'; INSERT INTO reserved_subdomains VALUES('legacy-name',?,1); DELETE FROM ops_projection_guard WHERE account_id=?`, a.ID, a.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if err = MigrateOperations(db); err != nil {
		t.Fatal(err)
	}
	var cached string
	if err = db.QueryRow(`SELECT plan FROM accounts WHERE id=?`, a.ID).Scan(&cached); err != nil || cached != "pro" {
		t.Fatal(cached, err)
	}
	// Schema reruns preserve records; a post-install forged cache still grants
	// nothing. Effective reservation ownership follows the entitlement reducer.
	var preserved string
	if err = db.QueryRow(`SELECT account_id FROM reserved_subdomains WHERE subdomain='legacy-name'`).Scan(&preserved); err != nil || preserved != a.ID {
		t.Fatal(preserved, err)
	}
	if owner, err := accounts.GetSubdomainOwner("legacy-name"); err != nil || owner != "" {
		t.Fatal(owner, err)
	}
	if _, err = ops.ProcessBillingEvent(context.Background(), BillingEvent{Provider: "stripe", ID: "evt_fake_revision", Type: "customer.subscription.updated", CustomerID: "cus_unknown", SubscriptionID: "sub_unknown", Revision: 99, Plan: "pro", Supported: true}); err == nil {
		t.Fatal("Stripe receipt revision conferred entitlement")
	}
}

func TestBillingReviewedMergedStateConvergesUnderReordering(t *testing.T) {
	for _, order := range [][]int{{0, 1, 2, 3, 4, 5}, {5, 4, 3, 2, 1, 0}, {2, 5, 0, 4, 1, 3}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			db, ops, a, _ := operationsFixture(t)
			ctx := context.Background()
			accounts := NewAccountStore(db)
			b, err := accounts.FindOrCreateByEmails([]string{"ordered-merge@example.invalid"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			for i, id := range []string{a.ID, b.ID} {
				customer, sub := fmt.Sprintf("cus_%d", i), fmt.Sprintf("sub_%d", i)
				if err = ops.BindBilling(ctx, operationsPrincipal(t, id), BillingMapping{Provider: "stripe", CustomerID: customer, SubscriptionID: sub, AccountID: id}); err != nil {
					t.Fatal(err)
				}
				if _, err = ops.ProcessBillingEvent(ctx, BillingEvent{Provider: "stripe", ID: fmt.Sprintf("evt_%d", i), Type: "customer.subscription.updated", CustomerID: customer, SubscriptionID: sub, Supported: true}); err != nil {
					t.Fatal(err)
				}
			}
			merged, err := accounts.FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github")
			if err != nil {
				t.Fatal(err)
			}
			principal := operationsPrincipal(t, merged.ID)
			latest := [2]int{-1, -1}
			for _, n := range order {
				binding := n % 2
				level := n / 2
				sub, customer := fmt.Sprintf("sub_%d", binding), fmt.Sprintf("cus_%d", binding)
				state, err := ops.AdminBillingStatus(ctx, principal, "stripe", sub)
				if err != nil {
					t.Fatal(err)
				}
				plan, status, paid := "free", "canceled", false
				if level == 0 {
					plan, status, paid = "pro", "active", true
				}
				// Subscription 0 finishes active, 1 finishes canceled. Intermediate
				// revocations arrive in every order, always with freshly read local CAS.
				if level == 2 && binding == 0 {
					plan, status, paid = "pro", "active", true
				}
				snap := BillingSnapshot{Provider: "stripe", CustomerID: customer, SubscriptionID: sub, AccountID: merged.ID, ExpectedVersion: state.Mapping.Version, Plan: plan, ProviderStatus: status, PaymentConfirmed: paid, ProviderReadAt: ops.now().Add(-time.Minute).Add(time.Duration(level) * time.Second), PriceID: "price_ordered", EvidenceSHA256: strings.Repeat("d", 64), EventIDs: []string{fmt.Sprintf("evt_%d", binding)}}
				_, err = ops.ApplyReviewedBilling(ctx, principal, []BillingSnapshot{snap})
				if level < latest[binding] {
					if err == nil {
						t.Fatal("stale review applied", n)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					latest[binding] = level
				}
				want := "free"
				if latest[0] == 0 || latest[0] == 2 || latest[1] == 0 {
					want = "pro"
				}
				requirePlan(t, db, merged.ID, want)
			}
		})
	}
}

func TestBillingBatchPreservesReservationsWhenEligibilityMoves(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	markBillingFixture(t, db)
	ctx := context.Background()
	accounts := NewAccountStore(db)
	b, err := accounts.FindOrCreateByEmails([]string{"batch-billing@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	bindFixture(t, ops, a.ID)
	if err = ops.BindBilling(ctx, operationsPrincipal(t, b.ID), BillingMapping{Provider: "fixture", CustomerID: "cus_second", SubscriptionID: "sub_second", AccountID: b.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = ops.ProcessBillingEvent(ctx, fixtureEvent("evt_first", 1, "pro")); err != nil {
		t.Fatal(err)
	}
	if _, err = ops.ProcessBillingEvent(ctx, BillingEvent{Provider: "fixture", ID: "evt_second", Type: "subscription.updated", CustomerID: "cus_second", SubscriptionID: "sub_second", Revision: 1, Plan: "free", Supported: true}); err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.ReserveSubdomain(merged.ID, "batch-name"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT OR IGNORE INTO ops_fixture VALUES(1,'disposable-local')`); err != nil {
		t.Fatal(err)
	}
	snaps := []BillingSnapshot{
		{Provider: "fixture", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: merged.ID, ExpectedVersion: 1, Revision: 2, Plan: "free"},
		{Provider: "fixture", CustomerID: "cus_second", SubscriptionID: "sub_second", AccountID: merged.ID, ExpectedVersion: 1, Revision: 2, Plan: "pro"},
	}
	if _, err = ops.Reconcile(ctx, operationsPrincipal(t, merged.ID), snaps, true); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, merged.ID, "pro")
	if owner, err := accounts.GetSubdomainOwner("batch-name"); err != nil || owner != merged.ID {
		t.Fatal("batch briefly revoked continuous paid eligibility", owner, err)
	}
}

func TestBillingLegacyReviewCannotBeOverwrittenByOlderEvidence(t *testing.T) {
	ops, snap, _ := orderedStripeFixture(t)
	ctx := context.Background()
	principal := operationsPrincipal(t, snap.AccountID)
	// Model the old hash-only review ledger with no durable verified state.
	if _, err := ops.db.Exec(`DELETE FROM ops_billing_states`); err != nil {
		t.Fatal(err)
	}
	if err := MigrateOperations(ops.db); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, ops.db, snap.AccountID, "free")
	if _, err := ops.ApplyReviewedBilling(ctx, principal, []BillingSnapshot{snap}); err == nil {
		t.Fatal("migration forgot the last legacy review's ordering floor")
	}
	freshTime := ops.now().Add(time.Second)
	ops.now = func() time.Time { return freshTime }
	snap.ProviderReadAt = freshTime
	if _, err := ops.ApplyReviewedBilling(ctx, principal, []BillingSnapshot{snap}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, ops.db, snap.AccountID, "pro")
}

func TestBillingLegacySignedCheckoutReceiptRemainsIdempotent(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	event := BillingEvent{Provider: "stripe", ID: "evt_legacy_signed", Type: "checkout.session.completed", CustomerID: "cus_legacy", SubscriptionID: "sub_legacy", Supported: true, PayloadSHA256: strings.Repeat("b", 64), CheckoutReference: a.ID}
	// The old normalizer omitted the reference but hashed the same signed body.
	legacy := event
	legacy.CheckoutReference = ""
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if _, err = db.Exec(`INSERT INTO ops_billing_events(provider,event_id,digest,event_type,subscription_id,customer_id,account_id,revision,plan,outcome,received_at) VALUES(?,?,?,?,?,?,'',0,'','reconciliation_required',?)`, event.Provider, event.ID, hex.EncodeToString(sum[:]), event.Type, event.SubscriptionID, event.CustomerID, ops.now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if result, err := ops.ProcessBillingEvent(context.Background(), event); err != nil || !result.Duplicate || result.State != "reconciliation_required" || result.AccountID != "" {
		t.Fatal(result, err)
	}
	requirePlan(t, db, a.ID, "free")
	event.CustomerID = "cus_different"
	if _, err := ops.ProcessBillingEvent(context.Background(), event); err == nil {
		t.Fatal("normalized identity conflict accepted")
	}
}
