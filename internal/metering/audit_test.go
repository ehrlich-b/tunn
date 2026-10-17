package metering

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"strings"
	"testing"
	"time"
)

func seedAudit(t *testing.T, db *sql.DB, e *pb.Event) {
	t.Helper()
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO meter_events(id,owner,endpoint,month,finished,data) VALUES(?,?,?,?,?,?)`, e.RequestId, e.Owner, e.Endpoint, e.Month, e.Finished, data); err != nil {
		t.Fatal(err)
	}
}
func TestAuditFiltersPaginationAndIsolation(t *testing.T) {
	s, db := fixture(t)
	ctx := context.Background()
	for i := 1; i <= 125; i++ {
		owner := "alice"
		if i > 120 {
			owner = "bob"
		}
		endpoint := "api"
		if i%2 == 0 {
			endpoint = "hooks"
		}
		seedAudit(t, db, &pb.Event{RequestId: fmt.Sprintf("%032x", i), Owner: owner, Endpoint: endpoint, StartedAt: testNow.Add(-time.Hour).UnixMilli(), Status: int32(200 + i%4*100), Finished: true})
	}
	ids := map[string]bool{}
	in := &pb.AuditRequest{Owner: "alice", Operation: "list", Limit: 17}
	for {
		out, err := s.Audit(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range out.Events {
			if ids[e.RequestId] || e.Owner != "alice" {
				t.Fatal(e)
			}
			ids[e.RequestId] = true
		}
		if !out.HasMore {
			break
		}
		last := out.Events[len(out.Events)-1]
		in.BeforeStarted, in.BeforeId = last.StartedAt, last.RequestId
	}
	if len(ids) != 120 {
		t.Fatal(len(ids))
	}
	out, err := s.Audit(ctx, &pb.AuditRequest{Owner: "alice", Operation: "list", Endpoint: "hooks", StatusClass: 2, Since: testNow.Add(-2 * time.Hour).UnixMilli(), Until: testNow.UnixMilli()})
	if err != nil || len(out.Events) != 30 {
		t.Fatalf("filter: %v %v", out, err)
	}
	for _, req := range []*pb.AuditRequest{{Owner: "bob", Operation: "list", RequestId: fmt.Sprintf("%032x", 1)}, {Owner: "alice", Operation: "list", Since: testNow.UnixMilli()}, {Owner: "alice", Operation: "list", Until: testNow.Add(-2 * time.Hour).UnixMilli()}} {
		out, err := s.Audit(ctx, req)
		if err != nil || len(out.Events) != 0 {
			t.Fatalf("isolation/time: %v %v", out, err)
		}
	}
	for _, req := range []*pb.AuditRequest{{Operation: "list"}, {Owner: "alice", Operation: "list", StatusClass: 6}, {Owner: "alice", Operation: "retention", RetentionDays: 8}, {Owner: "alice", Operation: "list", Limit: MaxEvents + 1}} {
		if _, err = s.Audit(ctx, req); err == nil {
			t.Fatal("accepted invalid", req)
		}
	}
}
func TestAuditRetentionIndexedBoundedAndPersistent(t *testing.T) {
	s, db := fixture(t)
	ctx := context.Background()
	for i := 0; i < 35; i++ {
		owner := fmt.Sprintf("owner%02d", i)
		if _, err := s.Audit(ctx, &pb.AuditRequest{Owner: owner, Operation: "retention", RetentionDays: 7}); err != nil {
			t.Fatal(err)
		}
		for n := 0; n < 105; n++ {
			seedAudit(t, db, &pb.Event{RequestId: fmt.Sprintf("%016x%016x", i, n), Owner: owner, Endpoint: "api", StartedAt: testNow.Add(-8 * 24 * time.Hour).UnixMilli(), Finished: n != 104})
		}
	}
	seedAudit(t, db, &pb.Event{RequestId: strings.Repeat("f", 32), Owner: "legacy", Endpoint: "api", StartedAt: testNow.AddDate(-2, 0, 0).UnixMilli(), Finished: true})
	seedAudit(t, db, &pb.Event{RequestId: strings.Repeat("e", 32), Owner: "owner00", Endpoint: "api", StartedAt: testNow.Add(-time.Hour).UnixMilli(), Finished: true})
	if _, err := db.Exec(`INSERT INTO meter_usage(owner,endpoint,caller,month,requests) VALUES('owner00','api','anonymous','2026-10',999)`); err != nil {
		t.Fatal(err)
	}
	next, n, err := s.SweepAuditRetention(ctx, "")
	if err != nil || n != 3200 || next != "owner31" {
		t.Fatalf("bounded %s %d %v", next, n, err)
	}
	_, n, err = s.SweepAuditRetention(ctx, next)
	if err != nil || n != 300 {
		t.Fatal(n, err)
	}
	for i := 0; i < 2; i++ {
		next = ""
		for {
			next, _, err = s.SweepAuditRetention(ctx, next)
			if err != nil {
				t.Fatal(err)
			}
			if next == "" {
				break
			}
		}
	}
	var remaining, requests int
	if err = db.QueryRow(`SELECT count(*) FROM meter_events`).Scan(&remaining); err != nil || remaining != 37 {
		t.Fatal(remaining, err)
	}
	if err = db.QueryRow(`SELECT requests FROM meter_usage`).Scan(&requests); err != nil || requests != 999 {
		t.Fatal(requests, err)
	}
	// Reinitialization keeps settings; incomplete requests are finalized by the existing restart recovery.
	restarted, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = s.now
	out, err := restarted.Audit(ctx, &pb.AuditRequest{Owner: "owner00", Operation: "list"})
	if err != nil || out.RetentionDays != 7 || len(out.Events) != 1 {
		t.Fatal(out, err)
	}
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT id FROM meter_events INDEXED BY meter_events_audit_retention WHERE owner=? AND finished=1 AND `+auditTimeExpression+`<? ORDER BY `+auditTimeExpression+` LIMIT 100`, "owner00", testNow.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	indexed := false
	for rows.Next() {
		var a, b, c int
		var detail string
		if err = rows.Scan(&a, &b, &c, &detail); err != nil {
			t.Fatal(err)
		}
		t.Log(detail)
		indexed = indexed || strings.Contains(detail, "SEARCH meter_events USING INDEX meter_events_audit_retention")
	}
	if !indexed {
		t.Fatal("retention query did not use timestamp index")
	}
}
func TestAuditMigrationOnlyAddsSchema(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE meter_events(id TEXT PRIMARY KEY,owner TEXT NOT NULL,endpoint TEXT NOT NULL,month TEXT NOT NULL,finished INTEGER NOT NULL,data BLOB NOT NULL); INSERT INTO meter_events VALUES('one','owner','api','2026-10',1,'{"started_at":1}'); CREATE TABLE untouched(value TEXT); INSERT INTO untouched VALUES('preserved');`); err != nil {
		t.Fatal(err)
	}
	var before, after string
	if err = db.QueryRow(`SELECT group_concat(sql,';') FROM sqlite_master WHERE type='table' ORDER BY name`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	s := &Store{db: db}
	if err = s.initAudit(); err != nil {
		t.Fatal(err)
	}
	if err = s.initAudit(); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT group_concat(sql,';') FROM sqlite_master WHERE type='table' AND name!='meter_audit_retention' ORDER BY name`).Scan(&after); err != nil || before != after {
		t.Fatal("existing schema changed", before, after, err)
	}
	var data, value string
	if err = db.QueryRow(`SELECT data FROM meter_events`).Scan(&data); err != nil || data != "{\"started_at\":1}" {
		t.Fatal(data, err)
	}
	if err = db.QueryRow(`SELECT value FROM untouched`).Scan(&value); err != nil || value != "preserved" {
		t.Fatal(value, err)
	}
}
func TestAuditRetentionWindowsAndDefault(t *testing.T) {
	s, db := fixture(t)
	ctx := context.Background()
	for i, age := range []int{1, 8, 31, 91} {
		seedAudit(t, db, &pb.Event{RequestId: fmt.Sprintf("%032x", i), Owner: "owner", Endpoint: "api", StartedAt: testNow.Add(-time.Duration(age) * 24 * time.Hour).UnixMilli(), Finished: true})
	}
	for _, v := range []struct {
		days int32
		want int
	}{{0, 4}, {7, 1}, {30, 2}, {90, 3}, {0, 4}} {
		if _, err := s.Audit(ctx, &pb.AuditRequest{Owner: "owner", Operation: "retention", RetentionDays: v.days}); err != nil {
			t.Fatal(err)
		}
		out, err := s.Audit(ctx, &pb.AuditRequest{Owner: "owner", Operation: "list"})
		if err != nil || len(out.Events) != v.want || out.RetentionDays != v.days {
			t.Fatal(v, out, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := s.SweepAuditRetention(canceled, ""); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestAuditRetentionJobStartsAndStops(t *testing.T) {
	s, db := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := s.Audit(ctx, &pb.AuditRequest{Owner: "owner", Operation: "retention", RetentionDays: 7}); err != nil {
		t.Fatal(err)
	}
	seedAudit(t, db, &pb.Event{RequestId: strings.Repeat("a", 32), Owner: "owner", Endpoint: "api", StartedAt: testNow.Add(-8 * 24 * time.Hour).UnixMilli(), Finished: true})
	done := make(chan struct{})
	go func() { s.RunAuditRetention(ctx); close(done) }()
	defer cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM meter_events`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("startup sweep did not delete expired records")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retention job did not stop")
	}
}

func TestAuditMigrationToleratesMalformedLegacyMetadata(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE meter_events(id TEXT PRIMARY KEY,owner TEXT NOT NULL,endpoint TEXT NOT NULL,month TEXT NOT NULL,finished INTEGER NOT NULL,data BLOB NOT NULL); INSERT INTO meter_events VALUES('broken','owner','api','2026-10',1,'{')`); err != nil {
		t.Fatal(err)
	}
	s, err := New(db)
	if err != nil {
		t.Fatal("additive migration rejected existing metadata", err)
	}
	if _, err = db.Exec(`INSERT INTO meter_events VALUES('another-broken','owner','api','2026-10',1,'{')`); err != nil {
		t.Fatal("index changed legacy write behavior", err)
	}
	out, err := s.Audit(context.Background(), &pb.AuditRequest{Owner: "owner", Operation: "list", StatusClass: 2})
	if err != nil || len(out.Events) != 0 {
		t.Fatal(out, err)
	}
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM meter_events WHERE data='{'`).Scan(&n); err != nil || n != 2 {
		t.Fatal("malformed rows changed", n, err)
	}
}
