package status

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func statusStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "status.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func statusSnapshot(t *testing.T, s *Store, now time.Time) Snapshot {
	t.Helper()
	v, err := s.Snapshot(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func recordStatus(t *testing.T, s *Store, now time.Time, health, ready bool) {
	t.Helper()
	if err := s.Record(context.Background(), Sample{now, health, ready}); err != nil {
		t.Fatal(err)
	}
}
func TestStatusTransitionsAndFreshness(t *testing.T) {
	s := statusStore(t)
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	if v := statusSnapshot(t, s, now); v.State != "unknown" || v.CheckedAt != nil || len(v.Days) != 90 || v.Observed != 0 {
		t.Fatal(v)
	}
	for _, tc := range []struct {
		health, ready bool
		want          string
	}{{true, true, "healthy"}, {true, false, "degraded"}, {false, false, "down"}, {false, true, "down"}, {true, true, "healthy"}} {
		now = now.Add(time.Minute)
		recordStatus(t, s, now, tc.health, tc.ready)
		if v := statusSnapshot(t, s, now); v.State != tc.want {
			t.Fatalf("state %s, want %s", v.State, tc.want)
		}
	}
	if v := statusSnapshot(t, s, now.Add(Freshness)); v.State != "healthy" {
		t.Fatal("freshness boundary", v.State)
	}
	if v := statusSnapshot(t, s, now.Add(Freshness+time.Second)); v.State != "unknown" || v.HealthState != "unknown" || v.ReadyState != "unknown" || v.CheckedAt == nil {
		t.Fatal("stale observation became healthy")
	}
	recordStatus(t, s, now.Add(10*time.Minute), true, true)
	if v := statusSnapshot(t, s, now); v.Observed != 5 || v.State != "healthy" {
		t.Fatal("future observation was counted", v)
	}
}
func TestStatusDailyCoverageAndWorstDuplicate(t *testing.T) {
	s := statusStore(t)
	midnight := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	recordStatus(t, s, midnight, true, true)
	if d := statusSnapshot(t, s, midnight).Days[89]; d.State != "healthy" || d.Observed != 1 || d.Expected != 1 {
		t.Fatal(d)
	}
	if d := statusSnapshot(t, s, midnight.Add(2*time.Minute)).Days[89]; d.State != "partial" || d.Observed != 1 || d.Expected != 3 {
		t.Fatal(d)
	}
	recordStatus(t, s, midnight.Add(10*time.Second), true, false)
	recordStatus(t, s, midnight.Add(20*time.Second), true, true)
	v := statusSnapshot(t, s, midnight.Add(30*time.Second))
	if d := v.Days[89]; d.State != "degraded" || d.Observed != 1 || d.Healthy != 0 {
		t.Fatal(d)
	}
	if v.State != "degraded" {
		t.Fatal(v.State)
	}
	recordStatus(t, s, midnight.Add(time.Minute), false, false)
	recordStatus(t, s, midnight.Add(2*time.Minute), true, true)
	v = statusSnapshot(t, s, midnight.Add(2*time.Minute))
	if d := v.Days[89]; d.State != "down" || d.Observed != 3 || d.Healthy != 1 {
		t.Fatal(d)
	}
	if v.State != "healthy" {
		t.Fatal("recovery failed", v.State)
	}
	if v.Days[88].State != "unknown" {
		t.Fatal("missing day invented")
	}
}
func TestStatusRetentionIncidentsAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "status.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	now := time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)
	old := now.Add(-Retention - time.Second)
	if err = s.BindOrigin(ctx, "https://relay.example"); err != nil {
		t.Fatal(err)
	}
	if err = s.BindOrigin(ctx, "https://relay.example"); err != nil {
		t.Fatal(err)
	}
	if err = s.BindOrigin(ctx, "https://other.example"); err == nil {
		t.Fatal("mixed origin accepted")
	}
	recordStatus(t, s, old, true, true)
	id, err := s.AddIncident(ctx, old, "Old resolved", "Opening")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ResolveIncident(ctx, old, id, "Resolved"); err != nil {
		t.Fatal(err)
	}
	open, err := s.AddIncident(ctx, old, "Old open", "Investigating")
	if err != nil {
		t.Fatal(err)
	}
	recordStatus(t, s, now, true, true)
	var n int
	if err = s.db.QueryRow(`SELECT count(*) FROM status_samples`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM status_incidents`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.BindOrigin(ctx, "https://other.example"); err == nil {
		t.Fatal("origin lost on restart")
	}
	v := statusSnapshot(t, s, now)
	if v.State != "healthy" || v.Observed != 1 || len(v.Incidents) != 1 || v.Incidents[0].ID != open {
		t.Fatal(v)
	}
	if err = s.ResolveIncident(ctx, now, open, "Recovered"); err != nil {
		t.Fatal(err)
	}
	if err = s.ResolveIncident(ctx, now, open, "Again"); err == nil {
		t.Fatal("resolved twice")
	}
	if err = s.ResolveIncident(ctx, now, 999, "Missing"); err == nil {
		t.Fatal("missing incident resolved")
	}
	v = statusSnapshot(t, s, now)
	if v.Incidents[0].ResolvedAt == nil || v.Incidents[0].Note != "Recovered" {
		t.Fatal(v.Incidents)
	}
	for _, tc := range []struct{ title, note string }{{"", "x"}, {"x", ""}, {strings.Repeat("x", 121), "x"}, {"x", strings.Repeat("x", 2001)}} {
		if _, err = s.AddIncident(ctx, now, tc.title, tc.note); err == nil {
			t.Fatal("invalid note accepted")
		}
	}
	if err = s.ResolveIncident(ctx, now, open, ""); err == nil {
		t.Fatal("invalid resolution accepted")
	}
	if _, err = Open(""); err == nil {
		t.Fatal("empty DB accepted")
	}
}

func TestStatusIncidentResponseBound(t *testing.T) {
	s := statusStore(t)
	now := time.Now().UTC()
	// Maximal escaping, within the documented per-note limit and list bound.
	// This checks the protocol's one-MiB limit with less than 200 KiB of input.
	for i := 0; i < 80; i++ {
		if _, err := s.AddIncident(context.Background(), now.Add(-time.Duration(i)*time.Minute), strings.Repeat("&", 120), strings.Repeat("&", 2000)); err != nil {
			t.Fatal(err)
		}
	}
	v := statusSnapshot(t, s, now)
	if len(v.Incidents) != 75 {
		t.Fatal("public incident bound", len(v.Incidents))
	}
	w := httptest.NewRecorder()
	Render(w, httptest.NewRequest("GET", "/status", nil), v, 200)
	if w.Body.Len() > 1<<20 || w.Code != 200 {
		t.Fatal("incident page exceeds relay response cap", w.Body.Len())
	}
}
