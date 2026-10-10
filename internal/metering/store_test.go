package metering

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"
)

var testNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return testNow }
	return s, db
}
func newGrant(t *testing.T, s *Store, requests, bytes, rate int64) *pb.Grant {
	t.Helper()
	digest := sha256.Sum256([]byte(fmt.Sprintf("secret-%d-%d-%d-%d", requests, bytes, rate, s.now().UnixNano())))
	g, err := s.CreateGrant(context.Background(), &pb.Grant{Owner: "owner@example.com", Endpoint: "api", Consumer: "agent@example.com", TokenSha256: digest[:], ExpiresAt: s.now().Add(24 * time.Hour).UnixMilli(), MonthlyRequests: requests, MonthlyBytes: bytes, RequestsPerMinute: rate})
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func event(g *pb.Grant, n int) *pb.Event {
	e := &pb.Event{RequestId: fmt.Sprintf("%032x", n), Owner: "owner@example.com", Endpoint: "api", Caller: "anonymous", AuthMethod: "none", Allowed: true, Reason: "allowed"}
	if g != nil {
		e.Caller = "grant:" + g.Id
		e.GrantId = g.Id
		e.AuthMethod = "grant"
	}
	return e
}
func admit(t *testing.T, s *Store, e *pb.Event) *pb.Decision {
	t.Helper()
	d, err := s.Admit(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func charge(t *testing.T, s *Store, id string, req, resp int64) *pb.Decision {
	t.Helper()
	d, err := s.Charge(context.Background(), &pb.ChargeRequest{RequestId: id, RequestBytes: req, ResponseBytes: resp})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func finish(t *testing.T, s *Store, e *pb.Event, resp int64) {
	t.Helper()
	_, err := s.Finish(context.Background(), &pb.Event{RequestId: e.RequestId, Status: 200, Forwarded: true, ResponseBytes: resp})
	if err != nil {
		t.Fatal(err)
	}
}
func export(t *testing.T, s *Store, month string) *pb.ExportResponse {
	t.Helper()
	out, err := s.Export(context.Background(), &pb.ExportRequest{Owner: "owner@example.com", Endpoint: "api", Month: month})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRequestBudgetConcurrentBoundaryAndIdempotency(t *testing.T) {
	s, _ := fixture(t)
	g := newGrant(t, s, 3, 0, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 1; i <= 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			e := event(g, n)
			d, err := s.Admit(context.Background(), e)
			if err != nil {
				t.Error(err)
				return
			}
			if d.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			} else if d.Status != 429 || d.Reason != "request_budget" || d.RetryAfter <= 0 {
				t.Errorf("decision=%+v", d)
			}
			_, err = s.Admit(context.Background(), e)
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if allowed != 3 {
		t.Fatalf("admitted %d, want 3", allowed)
	}
	out := export(t, s, "2026-10")
	if len(out.Usage) != 1 || out.Usage[0].Requests != 20 || out.Usage[0].AdmittedRequests != 3 || len(out.Events) != 20 {
		t.Fatalf("usage=%v events=%d", out.Usage, len(out.Events))
	}
}
func TestByteBudgetExactBoundaryPartialChunkAndShortWrite(t *testing.T) {
	s, _ := fixture(t)
	g := newGrant(t, s, 0, 10, 0)
	e := event(g, 1)
	if d := admit(t, s, e); !d.Allowed {
		t.Fatal(d)
	}
	d := charge(t, s, e.RequestId, 3, 7)
	if !d.Allowed || d.BytesRemaining != 0 {
		t.Fatalf("last byte=%+v", d)
	}
	d = charge(t, s, e.RequestId, 3, 7)
	if !d.Allowed || d.BytesRemaining != 0 {
		t.Fatalf("retry=%+v", d)
	}
	finish(t, s, e, 4) // three reserved egress bytes were never written
	if replay := admit(t, s, e); replay.BytesRemaining != 10 || replay.Reason != "allowed" || !replay.Allowed {
		t.Fatalf("admission replay lost original decision: %v", replay)
	}
	if out := export(t, s, "2026-10"); out.Usage[0].RequestBytes != 3 || out.Usage[0].ResponseBytes != 4 {
		t.Fatal(out)
	}
	e2 := event(g, 2)
	e2.ContentLength = 4
	if d := admit(t, s, e2); d.Allowed || d.Reason != "byte_budget" {
		t.Fatalf("known oversized body=%+v", d)
	}
	e3 := event(g, 3)
	if d := admit(t, s, e3); !d.Allowed {
		t.Fatal(d)
	}
	d = charge(t, s, e3.RequestId, 0, 8)
	if d.Allowed || d.Status != 429 || d.ResponseBytes != 3 || d.BytesRemaining != 0 {
		t.Fatalf("partial chunk=%+v", d)
	}
	finish(t, s, e3, 3)
	if d := admit(t, s, event(g, 4)); d.Allowed || d.Reason != "byte_budget" {
		t.Fatal(d)
	}
	if out := export(t, s, "2026-10"); out.Usage[0].RequestBytes+out.Usage[0].ResponseBytes != 10 {
		t.Fatal(out)
	}
}
func TestExpiryRevocationAndConsumerIsolation(t *testing.T) {
	s, _ := fixture(t)
	g := newGrant(t, s, 0, 0, 0)
	second := proto.Clone(g).(*pb.Grant)
	digest := sha256.Sum256([]byte("second consumer"))
	second.TokenSha256 = digest[:]
	second, err := s.CreateGrant(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	e := event(g, 1)
	admit(t, s, e)
	if _, err := s.RevokeGrant(context.Background(), &pb.Grant{Id: g.Id, Owner: g.Owner, Endpoint: "different"}); err == nil {
		t.Fatal("cross-endpoint revoke accepted")
	}
	if _, err := s.RevokeGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if d := charge(t, s, e.RequestId, 1, 0); d.Allowed || d.Reason != "grant_revoked" || d.Status != 403 {
		t.Fatal(d)
	}
	if d := admit(t, s, event(g, 2)); d.Allowed || d.Reason != "grant_revoked" {
		t.Fatal(d)
	}
	if d := admit(t, s, event(second, 3)); !d.Allowed {
		t.Fatal(d)
	}
	s.now = func() time.Time { return time.UnixMilli(second.ExpiresAt) }
	if d := admit(t, s, event(second, 4)); d.Allowed || d.Reason != "grant_expired" || d.Status != 403 {
		t.Fatal(d)
	}
	if d := charge(t, s, fmt.Sprintf("%032x", 3), 1, 0); d.Allowed || d.Reason != "grant_expired" {
		t.Fatal(d)
	}
}
func TestFixedMinuteRateAndUTCMonthlyReset(t *testing.T) {
	s, _ := fixture(t)
	now := time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC)
	s.now = func() time.Time { return now }
	g := newGrant(t, s, 2, 0, 1)
	if d := admit(t, s, event(g, 1)); !d.Allowed || d.RequestsRemaining != 1 {
		t.Fatal(d)
	}
	if d := admit(t, s, event(g, 2)); d.Allowed || d.Reason != "request_rate" || d.RetryAfter != 1 {
		t.Fatal(d)
	}
	now = now.Add(time.Second)
	if d := admit(t, s, event(g, 3)); !d.Allowed || d.RequestsRemaining != 1 {
		t.Fatal(d)
	}
	if out := export(t, s, "2026-10"); out.Usage[0].Requests != 2 || out.Usage[0].AdmittedRequests != 1 {
		t.Fatal(out)
	}
	if out := export(t, s, "2026-11"); out.Usage[0].Requests != 1 {
		t.Fatal(out)
	}
}
func TestRestartDurabilityAndInterruptedReservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meter.db")
	open := func() *Store {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		s, err := New(db)
		if err != nil {
			t.Fatal(err)
		}
		s.now = func() time.Time { return testNow }
		return s
	}
	s := open()
	g := newGrant(t, s, 2, 10, 1)
	e := event(g, 1)
	admit(t, s, e)
	charge(t, s, e.RequestId, 2, 3)
	finish(t, s, e, 3)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	s = open()
	// The fixed-minute limiter survives a restart, as do request/byte counters.
	if d := admit(t, s, event(g, 2)); d.Allowed || d.Reason != "request_rate" {
		t.Fatal(d)
	}
	s.now = func() time.Time { return testNow.Add(time.Minute) }
	e = event(g, 3)
	admit(t, s, e)
	charge(t, s, e.RequestId, 2, 3)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	s = open()
	defer func() { _ = s.db.Close() }()
	out := export(t, s, "2026-10")
	if out.Usage[0].AdmittedRequests != 2 || out.Usage[0].RequestBytes != 4 || out.Usage[0].ResponseBytes != 6 {
		t.Fatal(out)
	}
	if !out.Events[2].Finished || out.Events[2].Reason != "relay_restart" {
		t.Fatal(out.Events)
	}
	if d := admit(t, s, event(g, 4)); d.Allowed || d.Reason != "request_budget" {
		t.Fatal(d)
	}
	if _, err := s.RevokeGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	s = open()
	defer func() { _ = s.db.Close() }()
	if d := admit(t, s, event(g, 5)); d.Allowed || d.Reason != "grant_revoked" {
		t.Fatal(d)
	}
}
func TestBoundedRetentionPreservesCountersAndFailsClosed(t *testing.T) {
	s, db := fixture(t)
	s.maxEvents = 3
	s.maxUsage = 2
	s.maxGrants = 1
	g := newGrant(t, s, 5, 0, 0)
	for i := 1; i <= 5; i++ {
		e := event(g, i)
		admit(t, s, e)
		finish(t, s, e, 0)
	}
	out := export(t, s, "2026-10")
	if len(out.Events) != 3 || out.Usage[0].AdmittedRequests != 5 || !out.AuditTruncated || out.SchemaVersion != 1 || out.ByteUnit != "body_bytes" {
		t.Fatal(out)
	}
	if d := admit(t, s, event(g, 6)); d.Allowed {
		t.Fatal("retention reset budget")
	}
	e := event(nil, 7)
	admit(t, s, e)
	finish(t, s, e, 0)
	e = event(nil, 8)
	e.Caller = "email:new@example.com"
	if _, err := s.Admit(context.Background(), e); err != ErrCapacity {
		t.Fatalf("usage capacity=%v", err)
	}
	digest := sha256.Sum256([]byte("another token"))
	if _, err := s.CreateGrant(context.Background(), &pb.Grant{Owner: g.Owner, Endpoint: g.Endpoint, TokenSha256: digest[:], ExpiresAt: g.ExpiresAt}); err != ErrCapacity {
		t.Fatalf("grant capacity=%v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM meter_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count > 3 {
		t.Fatal(count)
	}
	// Old aggregate rows age out; the current depleted grant remains depleted.
	if _, err := db.Exec(`INSERT INTO meter_usage(owner,endpoint,caller,month) VALUES('old','api','anonymous','2020-01')`); err != nil {
		t.Fatal(err)
	}
	admit(t, s, event(g, 9))
	if err := db.QueryRow(`SELECT count(*) FROM meter_usage WHERE month='2020-01'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("old rollup retained")
	}
}
func TestActiveAuditCapacityCannotEvictInflight(t *testing.T) {
	s, _ := fixture(t)
	s.maxEvents = 2
	admit(t, s, event(nil, 1))
	admit(t, s, event(nil, 2))
	if _, err := s.Admit(context.Background(), event(nil, 3)); err != ErrCapacity {
		t.Fatal(err)
	}
	if out := export(t, s, "2026-10"); len(out.Events) != 2 || out.Usage[0].Requests != 2 {
		t.Fatal(out)
	}
}
func TestOwnerScopedResolveExportAndNoPayloads(t *testing.T) {
	s, db := fixture(t)
	g := newGrant(t, s, 0, 0, 0)
	e := event(g, 1)
	admit(t, s, e)
	finish(t, s, e, 0)
	out, err := s.Export(context.Background(), &pb.ExportRequest{Owner: "intruder", Endpoint: "api", Month: "2026-10"})
	if err != nil || len(out.Events) != 0 || len(out.Usage) != 0 {
		t.Fatalf("export=%v %v", out, err)
	}
	var digest []byte
	if err := db.QueryRow(`SELECT digest FROM meter_grants WHERE id=?`, g.Id).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*pb.ResolveRequest{{Owner: "intruder", Endpoint: g.Endpoint, TokenSha256: digest}, {Owner: g.Owner, Endpoint: "other", TokenSha256: digest}} {
		resolved, err := s.Resolve(context.Background(), r)
		if err != nil || resolved.Id != "" {
			t.Fatalf("cross-scope resolve=%v %v", resolved, err)
		}
	}
	var data []byte
	if err := db.QueryRow(`SELECT data FROM meter_events LIMIT 1`).Scan(&data); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-", "token_sha256", "headers", "body", "path", "agent@example.com"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("audit leaked %q: %s", forbidden, data)
		}
	}
	if len(g.TokenSha256) != 0 {
		t.Fatal("creation returned credential digest")
	}
}

func TestRetentionLeapDayKeepsThirteenCalendarMonths(t *testing.T) {
	s, db := fixture(t)
	s.now = func() time.Time { return time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC) }
	for _, month := range []string{"2023-01", "2023-02"} {
		if _, err := db.Exec(`INSERT INTO meter_usage(owner,endpoint,caller,month) VALUES('old','api','anonymous',?)`, month); err != nil {
			t.Fatal(err)
		}
	}
	admit(t, s, event(nil, 1))
	var oldest string
	if err := db.QueryRow(`SELECT min(month) FROM meter_usage`).Scan(&oldest); err != nil {
		t.Fatal(err)
	}
	if oldest != "2023-02" {
		t.Fatalf("leap-day retention dropped a valid month: %s", oldest)
	}
}

func TestOwnerBudgetsShareAllCallersAndTunnels(t *testing.T) {
	s, db := fixture(t)
	s.ownerRequests, s.ownerBytes = 2, 10
	g := newGrant(t, s, 100, 100, 0)
	first := event(g, 1)
	if d := admit(t, s, first); !d.Allowed || d.RequestsRemaining != 1 || d.BytesRemaining != 10 {
		t.Fatal(d)
	}
	charge(t, s, first.RequestId, 2, 3)
	finish(t, s, first, 3)
	second := event(nil, 2)
	second.Endpoint, second.Caller = "another", "email:alice@example.com"
	if d := admit(t, s, second); !d.Allowed || d.RequestsRemaining != 0 || d.BytesRemaining != 5 {
		t.Fatal(d)
	}
	if d := charge(t, s, second.RequestId, 2, 5); d.Allowed || d.Reason != "owner_byte_budget" || d.Status != 429 || d.RequestBytes != 2 || d.ResponseBytes != 3 || d.BytesRemaining != 0 {
		t.Fatal(d)
	}
	// A short write releases the reservation back to the shared owner budget.
	finish(t, s, second, 1)
	third := event(nil, 3)
	if d := admit(t, s, third); d.Allowed || d.Reason != "owner_request_budget" || d.RequestsRemaining != 0 || d.BytesRemaining != 2 {
		t.Fatal(d)
	}
	// Durable rollups, rather than retained audit events, enforce owner limits.
	if _, err := db.Exec(`DELETE FROM meter_events`); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(db, WithOwnerBudgets(2, 10))
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = s.now
	if d := admit(t, restarted, event(nil, 4)); d.Allowed || d.Reason != "owner_request_budget" {
		t.Fatal(d)
	}
	other := event(nil, 5)
	other.Owner = "other@example.com"
	if d := admit(t, restarted, other); !d.Allowed || d.BytesRemaining != 10 || d.RequestsRemaining != 1 {
		t.Fatal(d)
	}
	// Revocation still produces 403 even after the owner's cap is exhausted.
	if _, err := restarted.RevokeGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if d := admit(t, restarted, event(g, 6)); d.Allowed || d.Status != 403 || d.Reason != "grant_revoked" {
		t.Fatal(d)
	}
	restarted.now = func() time.Time { return testNow.AddDate(0, 1, 0) }
	if d := admit(t, restarted, event(nil, 7)); !d.Allowed || d.BytesRemaining != 10 || d.RequestsRemaining != 1 {
		t.Fatal(d)
	}
}

func TestOwnerBudgetsConcurrentAdmissionsAndBytes(t *testing.T) {
	for _, kind := range []string{"requests", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := fixture(t)
			if kind == "requests" {
				s.ownerRequests = 3
			} else {
				s.ownerBytes = 10
			}
			var wg sync.WaitGroup
			var mu sync.Mutex
			var admitted, charged int64
			for i := 1; i <= 20; i++ {
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					e := event(nil, n)
					e.Endpoint = fmt.Sprintf("api-%d", n)
					d, err := s.Admit(context.Background(), e)
					if err != nil {
						t.Error(err)
						return
					}
					if d.Allowed {
						mu.Lock()
						admitted++
						mu.Unlock()
						if kind == "bytes" {
							d, err = s.Charge(context.Background(), &pb.ChargeRequest{RequestId: e.RequestId, ResponseBytes: 3})
							if err != nil {
								t.Error(err)
								return
							}
							mu.Lock()
							charged += d.ResponseBytes
							mu.Unlock()
						}
					}
				}(i)
			}
			wg.Wait()
			if kind == "requests" && admitted != 3 || kind == "bytes" && charged != 10 {
				t.Fatalf("admissions=%d bytes=%d", admitted, charged)
			}
		})
	}
}

func TestOwnerByteAdmissionPreflight(t *testing.T) {
	s, _ := fixture(t)
	s.ownerBytes = 5
	e := event(nil, 1)
	e.ContentLength = 6
	if d := admit(t, s, e); d.Allowed || d.Reason != "owner_byte_budget" || d.BytesRemaining != 5 {
		t.Fatal(d)
	}
	e = event(nil, 2)
	e.ContentLength = 5
	if d := admit(t, s, e); !d.Allowed {
		t.Fatal(d)
	}
	if d := charge(t, s, e.RequestId, 5, 0); !d.Allowed || d.BytesRemaining != 0 {
		t.Fatal(d)
	}
	finish(t, s, e, 0)
	if d := admit(t, s, event(nil, 3)); d.Allowed || d.Reason != "owner_byte_budget" {
		t.Fatal(d)
	}
}

func TestUsageWindowOwnerTotalsAndRetention(t *testing.T) {
	s, _ := fixture(t)
	// Window crosses a UTC month and selects admissions, including denials.
	start := time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC)
	for i, offset := range []time.Duration{-2 * time.Hour, -time.Hour, -15 * time.Minute, 0} {
		s.now = func() time.Time { return start.Add(offset) }
		e := event(nil, i+1)
		if i == 2 {
			e.Endpoint, e.Caller = "another", "email:alice@example.com"
		}
		if i == 3 {
			e.Allowed, e.Reason, e.Status = false, "not_allowed", 403
		}
		admit(t, s, e)
		if e.Allowed {
			charge(t, s, e.RequestId, 2, 3)
			finish(t, s, e, 3)
		}
	}
	s.now = func() time.Time { return start.Add(time.Hour) }
	r := &pb.ExportRequest{Owner: "owner@example.com", Since: start.Add(-time.Hour).UnixMilli(), Until: start.Add(time.Hour).UnixMilli()}
	out, err := s.Export(context.Background(), r)
	if err != nil || out.OwnerUsage.Requests != 3 || out.OwnerUsage.AdmittedRequests != 2 || out.OwnerUsage.TotalBytes != 10 || len(out.Usage) != 3 || out.UsageTruncated || out.AuditTruncated {
		t.Fatalf("window=%v %v", out, err)
	}
	r.Endpoint = "api"
	out, err = s.Export(context.Background(), r)
	if err != nil || out.OwnerUsage.Requests != 2 || out.OwnerUsage.TotalBytes != 5 {
		t.Fatalf("filtered=%v %v", out, err)
	}
	r.Owner = "stranger@example.com"
	out, err = s.Export(context.Background(), r)
	if err != nil || len(out.Usage) != 0 || len(out.Events) != 0 || out.OwnerUsage.TotalBytes != 0 {
		t.Fatalf("owner isolation=%v %v", out, err)
	}
	// Eviction keeps monthly totals intact and flags window counts as incomplete.
	s.maxEvents = 1
	e := event(nil, 5)
	admit(t, s, e)
	finish(t, s, e, 0)
	r.Owner, r.Endpoint = "owner@example.com", ""
	out, err = s.Export(context.Background(), r)
	if err != nil || !out.AuditTruncated || !out.UsageTruncated || out.OwnerUsage.TotalBytes != 0 {
		t.Fatalf("truncated=%v %v", out, err)
	}
	out, err = s.Export(context.Background(), &pb.ExportRequest{Owner: r.Owner, Month: "2026-10"})
	if err != nil || out.OwnerUsage.TotalBytes != 5 || out.OwnerUsage.Requests != 3 || !out.AuditTruncated || out.UsageTruncated {
		t.Fatalf("monthly=%v %v", out, err)
	}
}

func TestListGrantsOwnerIsolationAndDurability(t *testing.T) {
	s, db := fixture(t)
	g := newGrant(t, s, 10, 20, 30)
	if _, err := s.RevokeGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"", "api", "other"} {
		out, err := restarted.ListGrants(context.Background(), &pb.ListGrantsRequest{Owner: g.Owner, Endpoint: endpoint})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint == "other" {
			if len(out.Grants) != 0 {
				t.Fatal(out)
			}
			continue
		}
		if len(out.Grants) != 1 || out.Grants[0].Id != g.Id || !out.Grants[0].Revoked || len(out.Grants[0].TokenSha256) > 0 || out.Grants[0].MonthlyRequests != 10 || out.Grants[0].MonthlyBytes != 20 || out.Grants[0].RequestsPerMinute != 30 {
			t.Fatal(out)
		}
	}
	if out, err := restarted.ListGrants(context.Background(), &pb.ListGrantsRequest{Owner: "stranger@example.com"}); err != nil || len(out.Grants) != 0 {
		t.Fatalf("owner isolation=%v %v", out, err)
	}
}
