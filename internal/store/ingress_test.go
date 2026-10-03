package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func ingressFixture(id string) IngressEvent {
	return IngressEvent{RequestID: id, AccountID: "owner", EndpointID: "tools", CallerID: "email:alice@example.test", AuthMethod: "bearer", Reason: "allow_list", Outcome: "completed", Status: 200, StartedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Forwarded: true, RequestBytes: 4, ResponseBytes: 6}
}

func TestIngressStoreIdempotencyPaginationAndIsolation(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewIngressStore(db)
	ctx := context.Background()
	e := ingressFixture("one")
	for i := 0; i < 2; i++ {
		if err := s.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	e.RequestID = "two"
	e.CallerID = "anonymous"
	e.AuthMethod = "none"
	e.Reason = "authentication_required"
	e.Outcome = "denied"
	e.Status = 401
	e.Forwarded = false
	e.RequestBytes = 0
	e.ResponseBytes = 0
	if err := s.Record(ctx, e); err != nil {
		t.Fatal(err)
	}
	e.RequestID = "three"
	e.AccountID = "other"
	if err := s.Record(ctx, e); err != nil {
		t.Fatal(err)
	}
	q := IngressQuery{AccountID: "owner", Month: "2026-10", Limit: 1}
	first, err := s.Export(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 1 || first.Events[0].RequestID != "one" || first.NextCursor == 0 || first.Billable {
		t.Fatalf("first page = %+v", first)
	}
	q.After = first.NextCursor
	second, err := s.Export(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Events) != 1 || second.Events[0].RequestID != "two" || second.NextCursor != 0 {
		t.Fatalf("second page = %+v", second)
	}
	q.After = 0
	q.Counters = true
	q.Limit = 500
	counters, err := s.Export(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(counters.Counters) != 2 {
		t.Fatalf("counters = %+v", counters)
	}
	c := counters.Counters[0]
	if c.Requests != 1 || c.Forwarded != 1 || c.RequestBytes != 4 || c.ResponseBytes != 6 {
		t.Fatalf("duplicate charged = %+v", c)
	}
	c = counters.Counters[1]
	if c.Denied != 1 || c.Forwarded != 0 || c.RequestBytes+c.ResponseBytes != 0 {
		t.Fatalf("denied metered = %+v", c)
	}
	q.EndpointID = "unowned"
	filtered, err := s.Export(ctx, q)
	if err != nil || len(filtered.Counters) != 0 {
		t.Fatalf("filtered=%+v err=%v", filtered, err)
	}
	q.EndpointID = ""
	q.Month = "2026-09"
	filtered, err = s.Export(ctx, q)
	if err != nil || len(filtered.Counters) != 0 {
		t.Fatalf("month isolation: %+v %v", filtered, err)
	}
}

func TestIngressStoreTransactionAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ingress.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Force the counter insert to fail; the event must roll back too.
	if _, err := db.Exec(`CREATE TRIGGER fail_counter BEFORE INSERT ON ingress_counters BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	s := NewIngressStore(db)
	if err := s.Record(ctx, ingressFixture("rollback")); err == nil {
		t.Fatal("expected rollback")
	}
	out, err := s.Export(ctx, IngressQuery{AccountID: "owner", Month: "2026-10", Limit: 10})
	if err != nil || len(out.Events) != 0 {
		t.Fatalf("partial commit: %+v %v", out, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_counter`); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(ctx, ingressFixture("durable")); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	out, err = NewIngressStore(db).Export(ctx, IngressQuery{AccountID: "owner", Month: "2026-10", Limit: 10})
	if err != nil || len(out.Events) != 1 || out.Events[0].RequestID != "durable" {
		t.Fatalf("reopen: %+v %v", out, err)
	}
}

func TestIngressValidation(t *testing.T) {
	q := IngressQuery{AccountID: "owner", Month: "2026-10", Limit: 10}
	for _, bad := range []IngressQuery{{AccountID: "owner", Month: "2026-13", Limit: 10}, {Month: "2026-10", Limit: 10}, {AccountID: "owner", Month: "2026-10", Limit: 501}, {AccountID: "owner", Month: "2026-10", Limit: 10, After: -1}} {
		if !errors.Is(bad.Validate(), ErrInvalidIngress) {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if q.Validate() != nil {
		t.Fatal("valid query rejected")
	}
	e := ingressFixture("validation")
	e.RequestBytes = -1
	if !errors.Is(e.Validate(), ErrInvalidIngress) {
		t.Fatal("negative units accepted")
	}
}

func BenchmarkIngressRecordSQLite(b *testing.B) {
	db, err := sql.Open("sqlite", filepath.Join(b.TempDir(), "ingress.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		b.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		b.Fatal(err)
	}
	s := NewIngressStore(db)
	e := ingressFixture("bench")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.RequestID = fmt.Sprintf("bench-%d", i)
		if err := s.Record(context.Background(), e); err != nil {
			b.Fatal(err)
		}
	}
}

func TestIngressAccountMergeKeepsHistoryAndActiveTunnels(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	accounts := NewAccountStore(db)
	ledger := NewIngressStore(db)
	ctx := context.Background()
	a, err := accounts.FindOrCreateByEmails([]string{"one@example.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	b, err := accounts.FindOrCreateByEmails([]string{"two@example.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{a.ID, b.ID} {
		e := ingressFixture(fmt.Sprint(i))
		e.AccountID = id
		if err := ledger.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
		if err := accounts.RecordUsage(id, 10); err != nil {
			t.Fatal(err)
		}
	}
	merged, err := accounts.FindOrCreateByEmails([]string{"one@example.test", "two@example.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	old := a.ID
	if old == merged.ID {
		old = b.ID
	}
	// An active publisher/retry still holds the secondary ID after the merge.
	e := ingressFixture("active-after-merge")
	e.AccountID = old
	if err := ledger.Record(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Record(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := accounts.RecordUsage(old, 5); err != nil {
		t.Fatal(err)
	}
	out, err := ledger.Export(ctx, IngressQuery{AccountID: merged.ID, Month: "2026-10", Limit: 500, Counters: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Counters) != 1 || out.Counters[0].Requests != 3 || out.Counters[0].RequestBytes != 12 {
		t.Fatalf("merged counters=%+v", out)
	}
	for _, id := range []string{merged.ID, old} {
		usage, err := accounts.GetMonthlyUsage(id)
		if err != nil || usage != 55 {
			t.Fatalf("merged quota=%d %v", usage, err)
		}
	}
	history, err := ledger.Export(ctx, IngressQuery{AccountID: merged.ID, Month: "2026-10", Limit: 500})
	if err != nil || len(history.Events) != 3 {
		t.Fatalf("history=%+v %v", history, err)
	}
	unrelated, err := ledger.Export(ctx, IngressQuery{AccountID: "unrelated", Month: "2026-10", Limit: 500})
	if err != nil || len(unrelated.Events) != 0 {
		t.Fatalf("cross-account=%+v %v", unrelated, err)
	}
}
