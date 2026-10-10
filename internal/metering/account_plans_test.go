package metering

import (
	"context"
	"fmt"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestAccountPlansImportRestartDowngradeAndFailClosed(t *testing.T) {
	_, db := fixture(t)
	if _, err := db.Exec(`CREATE TABLE accounts(id TEXT PRIMARY KEY, plan TEXT); CREATE TABLE account_usage(account_id TEXT, month TEXT, bytes_used INTEGER); INSERT INTO accounts VALUES('owner@example.com','free'); INSERT INTO account_usage VALUES('owner@example.com','2026-10',999999997)`); err != nil {
		t.Fatal(err)
	}
	s, err := New(db, WithAccountPlans())
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return testNow }
	e := event(nil, 1)
	d := admit(t, s, e)
	if !d.Allowed || d.BytesRemaining != 3 || d.RequestsRemaining != FreeMonthlyRequests-1 {
		t.Fatal(d)
	}
	d = charge(t, s, e.RequestId, 2, 4)
	if d.Allowed || d.RequestBytes != 2 || d.ResponseBytes != 1 || d.Reason != "owner_byte_budget" {
		t.Fatal(d)
	}
	finish(t, s, e, 1)
	// The completion mirror is not imported twice.
	if _, err := db.Exec(`UPDATE account_usage SET bytes_used=1000000000`); err != nil {
		t.Fatal(err)
	}
	s, err = New(db, WithAccountPlans())
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return testNow }
	out, err := s.Export(context.Background(), &pb.ExportRequest{Owner: e.Owner, Month: "2026-10"})
	if err != nil || out.OwnerUsage.TotalBytes != FreeMonthlyBytes {
		t.Fatalf("%v %v", out, err)
	}
	if d := admit(t, s, event(nil, 2)); d.Allowed || d.Reason != "owner_byte_budget" {
		t.Fatal(d)
	}
	if _, err := db.Exec(`UPDATE accounts SET plan='pro'`); err != nil {
		t.Fatal(err)
	}
	e = event(nil, 3)
	if d := admit(t, s, e); !d.Allowed || d.BytesRemaining != ProMonthlyBytes-FreeMonthlyBytes {
		t.Fatal(d)
	}
	// An existing publisher cannot retain an obsolete paid entitlement.
	if _, err := db.Exec(`UPDATE accounts SET plan='free'`); err != nil {
		t.Fatal(err)
	}
	if d := charge(t, s, e.RequestId, 0, 1); d.Allowed || d.ResponseBytes != 0 {
		t.Fatal(d)
	}
	s.now = func() time.Time { return testNow.AddDate(0, 1, 0) }
	if d := admit(t, s, event(nil, 4)); !d.Allowed || d.BytesRemaining != FreeMonthlyBytes {
		t.Fatal(d)
	}
	missing := event(nil, 5)
	missing.Owner = "missing-account"
	if _, err := s.Admit(context.Background(), missing); err == nil {
		t.Fatal("missing account admitted")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Admit(context.Background(), event(nil, 6)); err == nil {
		t.Fatal("closed ledger admitted")
	}
}

func TestAccountPlanRequestsShareTransportEndpoints(t *testing.T) {
	_, db := fixture(t)
	if _, err := db.Exec(`CREATE TABLE accounts(id TEXT PRIMARY KEY, plan TEXT); CREATE TABLE account_usage(account_id TEXT, month TEXT, bytes_used INTEGER); INSERT INTO accounts VALUES('owner@example.com','pro')`); err != nil {
		t.Fatal(err)
	}
	s, err := New(db, WithAccountPlans(), WithOwnerBudgets(4, 20))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return testNow }
	for i, endpoint := range []string{"http", "ws", "tcp", "mcp", "fifth"} {
		e := event(nil, i+1)
		e.Endpoint = endpoint
		e.Caller = fmt.Sprintf("caller-%d", i)
		d := admit(t, s, e)
		if d.Allowed != (i < 4) {
			t.Fatal(d)
		}
		if i == 4 && d.Reason != "owner_request_budget" {
			t.Fatal(d)
		}
	}
}
