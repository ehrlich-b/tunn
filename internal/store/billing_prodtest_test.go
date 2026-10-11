package store

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
)

func TestBillingConcurrentReplayCommitsOnce(t *testing.T) {
	db, ops, account, _ := operationsFixture(t)
	bindFixture(t, ops, account.ID)
	event := fixtureEvent("concurrent", 1, "pro")
	const deliveries = 12
	start := make(chan struct{})
	results := make(chan *BillingResult, deliveries)
	var wg sync.WaitGroup
	for i := 0; i < deliveries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out, err := ops.ProcessBillingEvent(context.Background(), event)
			if err != nil {
				t.Errorf("delivery failed: %v", err)
				return
			}
			results <- out
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	first := 0
	for out := range results {
		if out.State != "applied" || out.AccountID != account.ID || out.EventID != event.ID {
			t.Errorf("changed retry result: %+v", out)
		}
		if !out.Duplicate {
			first++
		}
	}
	var count, version, revision int
	if err := db.QueryRow("SELECT count(*) FROM ops_billing_events").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT version,revision FROM ops_billing_mappings").Scan(&version, &revision); err != nil {
		t.Fatal(err)
	}
	if first != 1 || count != 1 || version != 1 || revision != 1 {
		t.Fatalf("replay applied repeatedly: first=%d rows=%d version=%d revision=%d", first, count, version, revision)
	}
	requirePlan(t, db, account.ID, "pro")
}

func TestBillingSeededRevisionDeliveryConverges(t *testing.T) {
	for _, seed := range []int64{1, 17, 20261010} {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			db, ops, account, _ := operationsFixture(t)
			bindFixture(t, ops, account.ID)
			ctx := context.Background()
			if _, err := ops.Transition(ctx, operationsPrincipal(t, account.ID), account.ID, "suspended", "review hold", 0); err != nil {
				t.Fatal(err)
			}
			order := rand.New(rand.NewSource(seed)).Perm(16)
			var newest int64
			for _, n := range order {
				revision := int64(n + 1)
				plan := "free"
				if revision%2 == 0 {
					plan = "pro"
				}
				event := fixtureEvent(fmt.Sprintf("revision-%d", revision), revision, plan)
				want := "stale"
				if revision > newest {
					want, newest = "applied", revision
				}
				out, err := ops.ProcessBillingEvent(ctx, event)
				if err != nil || out.State != want || out.Duplicate {
					t.Fatalf("seed=%d revision=%d want=%s result=%v err=%v", seed, revision, want, out, err)
				}
				retry, err := ops.ProcessBillingEvent(ctx, event)
				if err != nil || !retry.Duplicate || retry.State != out.State {
					t.Fatalf("retry=%v err=%v", retry, err)
				}
			}
			requirePlan(t, db, account.ID, "pro")
			state, err := ops.LookupAccountStatus(ctx, account.ID)
			if err != nil || state.State != "suspended" || state.Version != 1 {
				t.Fatalf("billing changed suspension: %v %v", state, err)
			}
		})
	}
}

func TestBillingReconciliationBatchRollsBackEveryAccount(t *testing.T) {
	for _, failure := range []string{"invalid_second_snapshot", "second_write_failure"} {
		t.Run(failure, func(t *testing.T) {
			db, ops, first, _ := operationsFixture(t)
			ctx := context.Background()
			accounts := NewAccountStore(db)
			second, err := accounts.FindOrCreateByEmails([]string{"second@example.invalid"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			principal := operationsPrincipal(t, first.ID, second.ID)
			bindFixture(t, ops, first.ID)
			if err := ops.BindBilling(ctx, principal, BillingMapping{Provider: "fixture", CustomerID: "cus_second", SubscriptionID: "sub_second", AccountID: second.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("CREATE TABLE ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO ops_fixture VALUES(1,'disposable-local')"); err != nil {
				t.Fatal(err)
			}
			snapshots := []BillingSnapshot{
				{Provider: "fixture", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: first.ID, Plan: "pro", Revision: 1},
				{Provider: "fixture", CustomerID: "cus_second", SubscriptionID: "sub_second", AccountID: second.ID, Plan: "pro", Revision: 1},
			}
			if failure == "invalid_second_snapshot" {
				snapshots[1].ExpectedVersion = 1
			} else if _, err := db.Exec(`CREATE TRIGGER fail_second_plan BEFORE UPDATE OF plan ON accounts
WHEN NEW.primary_email='second@example.invalid' BEGIN SELECT RAISE(ABORT,'fixture plan write failure'); END`); err != nil {
				t.Fatal(err)
			}
			if _, err := ops.Reconcile(ctx, principal, snapshots, true); err == nil {
				t.Fatal("failed batch applied")
			}
			for _, account := range []*Account{first, second} {
				requirePlan(t, db, account.ID, "free")
			}
			var versions, events int
			if err := db.QueryRow("SELECT sum(version) FROM ops_billing_mappings").Scan(&versions); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow("SELECT count(*) FROM ops_billing_events").Scan(&events); err != nil {
				t.Fatal(err)
			}
			if versions != 0 || events != 0 {
				t.Fatalf("partial batch metadata survived: versions=%d events=%d", versions, events)
			}
		})
	}
}

func TestBillingConcurrentReconciliationHonorsReviewedVersion(t *testing.T) {
	db, ops, account, _ := operationsFixture(t)
	bindFixture(t, ops, account.ID)
	if _, err := db.Exec("CREATE TABLE ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO ops_fixture VALUES(1,'disposable-local')"); err != nil {
		t.Fatal(err)
	}
	principal := operationsPrincipal(t, account.ID)
	snapshot := BillingSnapshot{Provider: "fixture", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: account.ID, Plan: "pro", Revision: 1}
	const attempts = 8
	start := make(chan struct{})
	results := make(chan bool, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out, err := ops.Reconcile(context.Background(), principal, []BillingSnapshot{snapshot}, true)
			if err == nil && (len(out) != 1 || out[0].State != "applied") {
				t.Errorf("unexpected result: %v", out)
			}
			results <- err == nil
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for ok := range results {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("%d concurrent snapshots applied, want 1", winners)
	}
	requirePlan(t, db, account.ID, "pro")
	var version, events int
	if err := db.QueryRow("SELECT version FROM ops_billing_mappings").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM ops_billing_events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if version != 1 || events != 1 {
		t.Fatalf("snapshot CAS changed more than once: version=%d events=%d", version, events)
	}
}

func TestBillingInvalidMetadataDoesNotCommit(t *testing.T) {
	db, ops, account, _ := operationsFixture(t)
	bindFixture(t, ops, account.ID)
	for _, tc := range []struct {
		name string
		edit func(*BillingEvent)
	}{
		{"empty_provider", func(e *BillingEvent) { e.Provider = "" }},
		{"empty_id", func(e *BillingEvent) { e.ID = "" }},
		{"multiline_id", func(e *BillingEvent) { e.ID = "one\ntwo" }},
		{"empty_type", func(e *BillingEvent) { e.Type = "" }},
		{"negative_revision", func(e *BillingEvent) { e.Revision = -1 }},
		{"unsupported_plan", func(e *BillingEvent) { e.Plan = "enterprise" }},
		{"nonhex_digest", func(e *BillingEvent) { e.PayloadSHA256 = "invalid" }},
		{"short_digest", func(e *BillingEvent) { e.PayloadSHA256 = "1234" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := fixtureEvent(tc.name, 1, "pro")
			tc.edit(&event)
			if _, err := ops.ProcessBillingEvent(context.Background(), event); err == nil {
				t.Fatal("invalid event accepted")
			}
		})
	}
	requirePlan(t, db, account.ID, "free")
	var count int
	if err := db.QueryRow("SELECT count(*) FROM ops_billing_events").Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid input committed: rows=%d err=%v", count, err)
	}
}
