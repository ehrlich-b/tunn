package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func operationsPrincipal(t *testing.T, accounts ...string) AdminPrincipal {
	t.Helper()
	token := "fixture-operator-token-0123456789abcdef"
	digest := sha256.Sum256([]byte(token))
	p, err := AuthenticateAdmin([]AdminCredential{{Actor: "fixture-operator", TokenSHA256: hex.EncodeToString(digest[:]), Accounts: accounts}}, token)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func operationsFixture(t *testing.T) (*sql.DB, *OperationsStore, *Account, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operations.db")
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.FixedZone("fixture", -4*3600))
	ops := NewOperationsStore(db, func() time.Time { return now })
	a, err := NewAccountStore(db).FindOrCreateByEmails([]string{"first@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	return db, ops, a, path
}
func bindFixture(t *testing.T, ops *OperationsStore, id string) {
	t.Helper()
	if err := ops.BindBilling(context.Background(), operationsPrincipal(t, id), BillingMapping{Provider: "fixture", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: id}); err != nil {
		t.Fatal(err)
	}
}
func fixtureEvent(id string, revision int64, plan string) BillingEvent {
	return BillingEvent{Provider: "fixture", ID: id, Type: "subscription.updated", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", Revision: revision, Plan: plan, Supported: true}
}
func requirePlan(t *testing.T, db *sql.DB, id, plan string) {
	t.Helper()
	a, err := NewAccountStore(db).GetByID(id)
	if err != nil || a.Plan != plan {
		t.Fatalf("plan=%v err=%v want %s", a, err, plan)
	}
}
func TestAccountOperationsTransitionsRestartAndRollback(t *testing.T) {
	db, ops, a, path := operationsFixture(t)
	ctx := context.Background()
	p := operationsPrincipal(t, a.ID)
	if _, err := ops.Transition(ctx, AdminPrincipal{}, a.ID, "suspended", "fixture", 0); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if _, err := ops.Transition(ctx, operationsPrincipal(t, "another-account"), a.ID, "suspended", "fixture", 0); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if err := NewAccountStore(db).RecordUsage(a.ID, 12345); err != nil {
		t.Fatal(err)
	}
	state, err := ops.Transition(ctx, p, a.ID, "suspended", "operator investigation", 0)
	if err != nil || state.Version != 1 || state.State != "suspended" || state.Actor != "fixture-operator" || state.ChangedAt != "2026-10-10T16:00:00Z" {
		t.Fatalf("transition=%+v %v", state, err)
	}
	if _, err = ops.Transition(ctx, p, a.ID, "active", "stale resume", 0); !errors.Is(err, ErrVersionConflict) {
		t.Fatal(err)
	}
	if err = NewAccountStore(db).UpdatePlan(a.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	ops = NewOperationsStore(reopened, ops.now)
	state, err = ops.LookupAccountStatus(ctx, a.ID)
	if err != nil || state.State != "suspended" || state.Version != 1 {
		t.Fatalf("restart=%+v %v", state, err)
	}
	if _, err = reopened.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON ops_account_audit BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = ops.Transition(ctx, p, a.ID, "active", "ready", 1); err == nil {
		t.Fatal("storage failure was ignored")
	}
	state, err = ops.LookupAccountStatus(ctx, a.ID)
	if err != nil || state.State != "suspended" || state.Version != 1 {
		t.Fatal("state escaped failed transaction", state, err)
	}
	if _, err = reopened.Exec("DROP TRIGGER fail_audit"); err != nil {
		t.Fatal(err)
	}
	state, err = ops.Transition(ctx, p, a.ID, "active", "review completed", 1)
	if err != nil || state.Version != 2 {
		t.Fatal(state, err)
	}
	if bytes, err := NewAccountStore(reopened).GetMonthlyUsage(a.ID); err != nil || bytes != 12345 {
		t.Fatal(bytes, err)
	}
	var audits int
	if err = reopened.QueryRow("SELECT count(*) FROM ops_account_audit").Scan(&audits); err != nil || audits != 2 {
		t.Fatal(audits, err)
	}
}
func TestAccountOperationsMergePreservesControlsAndUsage(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	accounts := NewAccountStore(db)
	b, err := accounts.FindOrCreateByEmails([]string{"second@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.UpdatePlan(b.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if _, err = ops.Transition(ctx, operationsPrincipal(t, a.ID), a.ID, "suspended", "operator investigation", 0); err != nil {
		t.Fatal(err)
	}
	bindFixture(t, ops, a.ID)
	for _, item := range []struct {
		id string
		n  int64
	}{{a.ID, 100}, {b.ID, 200}} {
		if err = accounts.RecordUsage(item.id, item.n); err != nil {
			t.Fatal(err)
		}
	}
	merged, err := accounts.FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	state, err := ops.LookupAccountStatus(ctx, a.ID)
	if err != nil || state.AccountID != merged.ID || state.State != "suspended" || state.Version != 2 {
		t.Fatal(state, err)
	}
	if _, err = ops.ProcessBillingEvent(ctx, fixtureEvent("upgrade", 1, "pro")); err != nil {
		t.Fatal(err)
	}
	state, err = ops.LookupAccountStatus(ctx, b.ID)
	if err != nil || state.State != "suspended" {
		t.Fatal(state, err)
	}
	if err = accounts.RecordUsage(a.ID, 50); err != nil {
		t.Fatal(err)
	}
	if used, err := accounts.GetMonthlyUsage(merged.ID); err != nil || used != 350 {
		t.Fatal(used, err)
	}
	if _, err = ops.Transition(ctx, operationsPrincipal(t, a.ID), a.ID, "active", "wrong surviving scope", 2); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if _, err = ops.Transition(ctx, operationsPrincipal(t, merged.ID), merged.ID, "active", "merge reviewed", 2); err != nil {
		t.Fatal(err)
	}
}
func TestAccountOperationsBillingPermutations(t *testing.T) {
	for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		t.Run(string(rune('a'+order[0]))+string(rune('a'+order[1]))+string(rune('a'+order[2])), func(t *testing.T) {
			db, ops, a, path := operationsFixture(t)
			bindFixture(t, ops, a.ID)
			events := []BillingEvent{fixtureEvent("one", 1, "pro"), fixtureEvent("two", 2, "free"), fixtureEvent("three", 3, "pro")}
			for _, i := range order {
				if _, err := ops.ProcessBillingEvent(context.Background(), events[i]); err != nil {
					t.Fatal(err)
				}
			}
			requirePlan(t, db, a.ID, "pro")
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenLocal(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reopened.Close() }()
			ops = NewOperationsStore(reopened, nil)
			for _, e := range events {
				r, err := ops.ProcessBillingEvent(context.Background(), e)
				if err != nil || !r.Duplicate {
					t.Fatal(r, err)
				}
			}
			var count int
			if err = reopened.QueryRow("SELECT count(*) FROM ops_billing_events").Scan(&count); err != nil || count != 3 {
				t.Fatal(count, err)
			}
			requirePlan(t, reopened, a.ID, "pro")
		})
	}
}
func TestAccountOperationsBillingFailureAndAmbiguity(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	bindFixture(t, ops, a.ID)
	if _, err := db.Exec(`CREATE TRIGGER fail_event BEFORE INSERT ON ops_billing_events BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ProcessBillingEvent(ctx, fixtureEvent("one", 1, "pro")); err == nil {
		t.Fatal("failed event was accepted")
	}
	requirePlan(t, db, a.ID, "free")
	if _, err := db.Exec("DROP TRIGGER fail_event"); err != nil {
		t.Fatal(err)
	}
	r, err := ops.ProcessBillingEvent(ctx, fixtureEvent("one", 1, "pro"))
	if err != nil || r.State != "applied" {
		t.Fatal(r, err)
	}
	if _, err = ops.ProcessBillingEvent(ctx, fixtureEvent("one", 1, "free")); err == nil {
		t.Fatal("conflicting event ID accepted")
	}
	for _, e := range []BillingEvent{fixtureEvent("equal-conflict", 1, "free"), fixtureEvent("unordered", 0, "free"), {Provider: "stripe", ID: "deleted", Type: "customer.subscription.deleted", CustomerID: "cus_unknown", SubscriptionID: "sub_unknown", Supported: true}} {
		r, err = ops.ProcessBillingEvent(ctx, e)
		if err != nil || r.State != "reconciliation_required" {
			t.Fatal(r, err)
		}
		requirePlan(t, db, a.ID, "pro")
	}
	r, err = ops.ProcessBillingEvent(ctx, BillingEvent{Provider: "stripe", ID: "unknown", Type: "invoice.future"})
	if err != nil || r.State != "ignored" {
		t.Fatal(r, err)
	}
	b, err := NewAccountStore(db).FindOrCreateByEmails([]string{"other@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	m := BillingMapping{Provider: "fixture", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: b.ID}
	if err = ops.BindBilling(ctx, operationsPrincipal(t, a.ID), m); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if err = ops.BindBilling(ctx, operationsPrincipal(t, b.ID), m); err == nil {
		t.Fatal("mapping reassign accepted")
	}
	m.CustomerID, m.SubscriptionID = "cus_other", "sub_other"
	if err = ops.BindBilling(ctx, operationsPrincipal(t, b.ID), m); err != nil {
		t.Fatal(err)
	}
	merged, err := NewAccountStore(db).FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	r, err = ops.ProcessBillingEvent(ctx, fixtureEvent("after-conflicting-merge", 2, "free"))
	if err != nil || r.State != "reconciliation_required" || r.AccountID != merged.ID {
		t.Fatal(r, err)
	}
	requirePlan(t, db, merged.ID, "pro")
}
func TestAccountOperationsReconciliationDryRunAndAtomicApply(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	bindFixture(t, ops, a.ID)
	p := operationsPrincipal(t, a.ID)
	snap := BillingSnapshot{Provider: "fixture", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: a.ID, ExpectedVersion: 0, Revision: 10, Plan: "pro"}
	changes, err := ops.Reconcile(ctx, p, []BillingSnapshot{snap}, false)
	if err != nil || changes[0].State != "change_expected" {
		t.Fatal(changes, err)
	}
	requirePlan(t, db, a.ID, "free")
	if _, err = ops.Reconcile(ctx, p, []BillingSnapshot{snap}, true); err == nil {
		t.Fatal("unmarked database mutated")
	}
	if _, err = db.Exec("CREATE TABLE ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO ops_fixture VALUES(1,'disposable-local')"); err != nil {
		t.Fatal(err)
	}
	if _, err = ops.Transition(ctx, p, a.ID, "suspended", "operator hold", 0); err != nil {
		t.Fatal(err)
	}
	changes, err = ops.Reconcile(ctx, p, []BillingSnapshot{snap}, true)
	if err != nil || changes[0].State != "applied" {
		t.Fatal(changes, err)
	}
	requirePlan(t, db, a.ID, "pro")
	state, err := ops.LookupAccountStatus(ctx, a.ID)
	if err != nil || state.State != "suspended" {
		t.Fatal(state, err)
	}
	if _, err = ops.Reconcile(ctx, p, []BillingSnapshot{snap}, true); err == nil {
		t.Fatal("stale reviewed snapshot reapplied")
	}
	snap.ExpectedVersion = 1
	changes, err = ops.Reconcile(ctx, p, []BillingSnapshot{snap}, true)
	if err != nil || changes[0].State != "current" {
		t.Fatal(changes, err)
	}
	snap.Plan = "free"
	if _, err = ops.Reconcile(ctx, p, []BillingSnapshot{snap}, true); err == nil {
		t.Fatal("same revision conflict applied")
	}
}
func TestAccountOperationsReportsAndMigrationRerun(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	p := operationsPrincipal(t, a.ID)
	for _, bad := range []struct{ category, endpoint string }{{"body", "api"}, {"abuse", "https://request-body.invalid"}, {"abuse", "api\nbody"}} {
		if _, err := ops.IntakeReport(ctx, a.ID, bad.category, bad.endpoint); err == nil {
			t.Fatal("invalid report accepted")
		}
	}
	r, err := ops.IntakeReport(ctx, a.ID, "abuse", "api")
	if err != nil || r.State != "received" {
		t.Fatal(r, err)
	}
	if _, err = ops.RespondReport(ctx, operationsPrincipal(t, "other"), r.ID, "triaged", 1); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	for _, state := range []string{"triaged", "action_taken", "closed"} {
		r, err = ops.RespondReport(ctx, p, r.ID, state, r.Version)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = ops.RespondReport(ctx, p, r.ID, "received", r.Version); err == nil {
		t.Fatal("closed report reopened implicitly")
	}
	for i := 0; i < 4; i++ {
		if _, err = ops.IntakeReport(ctx, a.ID, "availability", "api"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = ops.IntakeReport(ctx, a.ID, "billing", "api"); err == nil {
		t.Fatal("report rate limit absent")
	}
	for i := 0; i < 3; i++ {
		if err = MigrateOperations(db); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = db.QueryRow("SELECT count(*) FROM ops_reports").Scan(&count); err != nil || count != 5 {
		t.Fatal(count, err)
	}
}

func TestAccountOperationsReconciliationResolvesOnlyReviewedEvents(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	bindFixture(t, ops, a.ID)
	principal := operationsPrincipal(t, a.ID)
	for _, id := range []string{"reviewed", "newer-unreviewed"} {
		if r, err := ops.ProcessBillingEvent(ctx, fixtureEvent(id, 0, "free")); err != nil || r.State != "reconciliation_required" {
			t.Fatal(r, err)
		}
	}
	if _, err := db.Exec(`CREATE TABLE ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO ops_fixture VALUES(1,'disposable-local');`); err != nil {
		t.Fatal(err)
	}
	snap := BillingSnapshot{Provider: "fixture", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: a.ID, Plan: "pro", Revision: 1, EventIDs: []string{"reviewed"}}
	if _, err := db.Exec(`CREATE TRIGGER fail_reconcile BEFORE INSERT ON ops_billing_events WHEN NEW.event_type='snapshot.reconciled' BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.Reconcile(ctx, principal, []BillingSnapshot{snap}, true); err == nil {
		t.Fatal("failed reconciliation escaped rollback")
	}
	requirePlan(t, db, a.ID, "free")
	if r, err := ops.ProcessBillingEvent(ctx, fixtureEvent("reviewed", 0, "free")); err != nil || r.State != "reconciliation_required" {
		t.Fatal(r, err)
	}
	if _, err := db.Exec("DROP TRIGGER fail_reconcile"); err != nil {
		t.Fatal(err)
	}
	if result, err := ops.Reconcile(ctx, principal, []BillingSnapshot{snap}, true); err != nil || result[0].State != "applied" {
		t.Fatal(result, err)
	}
	for _, id := range []string{"reviewed", "newer-unreviewed"} {
		r, err := ops.ProcessBillingEvent(ctx, fixtureEvent(id, 0, "free"))
		want := "reconciled"
		if id == "newer-unreviewed" {
			want = "reconciliation_required"
		}
		if err != nil || r.State != want || !r.Duplicate {
			t.Fatal(r, err)
		}
	}
	var actor, reference string
	if err := db.QueryRow(`SELECT actor,event_id FROM ops_billing_events WHERE event_type='snapshot.reconciled'`).Scan(&actor, &reference); err != nil || actor != "fixture-operator" || reference == "" {
		t.Fatal(actor, reference, err)
	}
	var resolvedBy string
	if err := db.QueryRow(`SELECT reconciled_by FROM ops_billing_events WHERE event_id='reviewed'`).Scan(&resolvedBy); err != nil || resolvedBy != reference {
		t.Fatal(resolvedBy, err)
	}
	snap.ExpectedVersion = 1
	snap.Revision = 2
	snap.Plan = "free"
	snap.EventIDs = []string{"newer-unreviewed"}
	if _, err := ops.Reconcile(ctx, principal, []BillingSnapshot{snap}, true); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "free")
}
func TestAccountOperationsConcurrentVersionAndMergeRollback(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	p := operationsPrincipal(t, a.ID)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, err := ops.Transition(ctx, p, a.ID, "suspended", "concurrent fixture", 0); results <- err }()
	}
	success := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("concurrent transitions", success)
	}
	accounts := NewAccountStore(db)
	b, err := accounts.FindOrCreateByEmails([]string{"merge-rollback@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.UpdatePlan(b.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if err = accounts.RecordUsage(a.ID, 12); err != nil {
		t.Fatal(err)
	}
	if err = accounts.RecordUsage(b.ID, 34); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER fail_merge BEFORE INSERT ON ops_account_audit WHEN NEW.actor='system:account-merge' BEGIN SELECT RAISE(ABORT,'fixture merge failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = accounts.FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github"); err == nil {
		t.Fatal("failed merge committed")
	}
	for _, item := range []struct {
		id   string
		used int64
	}{{a.ID, 12}, {b.ID, 34}} {
		if used, err := accounts.GetMonthlyUsage(item.id); err != nil || used != item.used {
			t.Fatal("failed merge moved usage", used, err)
		}
	}
	if _, err = db.Exec("DROP TRIGGER fail_merge"); err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	state, err := ops.LookupAccountStatus(ctx, merged.ID)
	if err != nil || state.State != "suspended" {
		t.Fatal(state, err)
	}
	var original int
	if err = db.QueryRow("SELECT count(*) FROM ops_account_audit WHERE account_id=? AND original_account_id=?", merged.ID, a.ID).Scan(&original); err != nil || original != 1 {
		t.Fatal("audit provenance lost", original, err)
	}
}
