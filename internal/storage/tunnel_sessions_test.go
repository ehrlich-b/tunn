package storage

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
)

func TestTunnelSessionFencesReorderedCleanup(t *testing.T) {
	s := newTestLocalStorage(t)
	ctx := context.Background()
	owner := testLocalAccount(t, s, "owner@example.test")
	other := testLocalAccount(t, s, "other@example.test")
	admit := func(session string) {
		t.Helper()
		r, err := s.RegisterTunnelSession(ctx, "reserved", owner, "node", session)
		if err != nil || !r.Allowed {
			t.Fatalf("admit %s: %+v %v", session, r, err)
		}
	}
	report := func(session, operation string) {
		t.Helper()
		_, err := s.TunnelAlert(ctx, &pb.TunnelAlertRequest{AccountId: owner, Tunnel: "reserved", Session: session, Operation: operation})
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(session string, online int) {
		t.Helper()
		count, err := s.GetTunnelCount(ctx, owner)
		if err != nil || count != 1 {
			t.Fatalf("active count=%d err=%v", count, err)
		}
		var got string
		var live int
		if err := s.db.QueryRow(`SELECT session,online FROM tunnel_availability WHERE tunnel='reserved'`).Scan(&got, &live); err != nil || got != session || live != online {
			t.Fatalf("availability=%s/%d want=%s/%d err=%v", got, live, session, online, err)
		}
	}
	admit("old")
	report("old", "up")
	if err := s.UnregisterTunnelSession(ctx, "reserved", "old"); err != nil {
		t.Fatal(err)
	}
	// Retired generations cannot resurrect themselves through a late heartbeat.
	report("old", "heartbeat")
	if count, _ := s.GetTunnelCount(ctx, owner); count != 0 {
		t.Fatal("retired heartbeat revived registration")
	}
	if r, err := s.RegisterTunnel(ctx, "reserved", owner, "legacy-node"); err != nil || r.Allowed {
		t.Fatal("unversioned admission discarded generation fence", r, err)
	}
	admit("new")
	// Delayed down/up/heartbeat and cleanup arrive before the new up report.
	for _, op := range []string{"down", "graceful", "up", "heartbeat"} {
		report("old", op)
	}
	if err := s.UnregisterTunnelSession(ctx, "reserved", "old"); err != nil {
		t.Fatal(err)
	}
	if err := s.UnregisterTunnel(ctx, "reserved"); err == nil {
		t.Fatal("unversioned cleanup claimed success on a versioned registration")
	}
	check("old", 1)
	// Expiring the previous availability row cannot delete the new admission.
	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := s.ClaimTunnelAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	check("old", 0)
	report("new", "up")
	// Reordered cleanup after replacement is online cannot mark it down.
	var wg sync.WaitGroup
	for _, op := range []string{"down", "graceful", "up", "heartbeat"} {
		wg.Add(1)
		go func(op string) {
			defer wg.Done()
			_, err := s.TunnelAlert(ctx, &pb.TunnelAlertRequest{AccountId: owner, Tunnel: "reserved", Session: "old", Operation: op})
			if err != nil {
				t.Error(err)
			}
		}(op)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.UnregisterTunnelSession(ctx, "reserved", "old"); err != nil {
			t.Error(err)
		}
	}()
	wg.Wait()
	check("new", 1)
	if r, err := s.RegisterTunnelSession(ctx, "reserved", other, "node", "attacker"); err != nil || r.Allowed {
		t.Fatalf("different owner admitted: %+v %v", r, err)
	}
	if err := s.UnregisterTunnelSession(ctx, "reserved", "new"); err != nil {
		t.Fatal(err)
	}
	if r, err := s.RegisterTunnelSession(ctx, "reserved", other, "node", "attacker-offline"); err != nil || r.Allowed {
		t.Fatalf("reservation stolen while offline: %+v %v", r, err)
	}
	t.Log("old cleanup fenced before/after replacement up; expiry fenced; durable reservation preserved")
}

func TestTunnelSessionParallelAdmission(t *testing.T) {
	s := newTestLocalStorage(t)
	ctx := context.Background()
	owner := testLocalAccount(t, s, "owner@example.test")
	other := testLocalAccount(t, s, "other@example.test")
	if err := s.accounts.ReserveSubdomain(owner, "parallel"); err != nil {
		t.Fatal(err)
	}
	first, err := s.RegisterTunnelSession(ctx, "parallel", owner, "node", "old")
	if err != nil || !first.Allowed {
		t.Fatal(first, err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	winners := make(chan string, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			id := owner
			if i%2 == 1 {
				id = other
			}
			session := fmt.Sprint("candidate-", i)
			r, err := s.RegisterTunnelSessionAfter(ctx, "parallel", id, "node", session, "old")
			if err != nil {
				t.Error(err)
				return
			}
			if r.Allowed {
				if id != owner {
					t.Error("different owner admitted")
				}
				winners <- session
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if err := s.UnregisterTunnelSession(ctx, "parallel", "old"); err != nil {
			t.Error(err)
		}
	}()
	close(start)
	wg.Wait()
	close(winners)
	var winner string
	for w := range winners {
		if winner != "" {
			t.Fatal("two active admissions", winner, w)
		}
		winner = w
	}
	// If all admissions preceded teardown, retry once after its explicit join.
	if winner == "" {
		r, err := s.RegisterTunnelSession(ctx, "parallel", owner, "node", "after")
		if err != nil || !r.Allowed {
			t.Fatal(r, err)
		}
	}
	count, err := s.GetTunnelCount(ctx, owner)
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
	t.Log("parallel/reordered old release and admissions yield exactly one owning publisher")
}

func TestTunnelSessionReleaseBeforeAdmission(t *testing.T) {
	s := newTestLocalStorage(t)
	ctx := context.Background()
	owner := testLocalAccount(t, s, "owner@example.test")
	const name = "pending"
	if err := s.UnregisterTunnelSession(ctx, name, "pending-session"); err != nil {
		t.Fatal(err)
	}
	denyRetired := func() {
		t.Helper()
		r, err := s.RegisterTunnelSession(ctx, name, owner, "node", "pending-session")
		if err != nil || r.Allowed || r.Reason != "publisher generation retired" {
			t.Fatalf("released pending admission was revived: %+v %v", r, err)
		}
	}
	denyRetired()
	if r, err := s.RegisterTunnel(ctx, name, owner, "legacy"); err != nil || r.Allowed {
		t.Fatal("legacy admission discarded pending-session fence", r, err)
	}
	r, err := s.RegisterTunnelSession(ctx, name, owner, "node", "replacement")
	if err != nil || !r.Allowed {
		t.Fatal(r, err)
	}
	// Repeated cleanup must retain the retired session even when the last
	// active generation belongs to a replacement, and after that one leaves.
	if err := s.UnregisterTunnelSession(ctx, name, "pending-session"); err != nil {
		t.Fatal(err)
	}
	denyRetired()
	if count, err := s.GetTunnelCount(ctx, owner); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err := s.UnregisterTunnelSession(ctx, name, "replacement"); err != nil {
		t.Fatal(err)
	}
	denyRetired()
	if count, err := s.GetTunnelCount(ctx, owner); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	t.Log("release fences pending admission before, during and after replacement")
}
