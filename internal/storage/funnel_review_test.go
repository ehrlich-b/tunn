package storage

import (
	"context"
	pb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"testing"
)

func TestFunnelOnlyAfterAdmission(t *testing.T) {
	s := newTestLocalStorage(t)
	id := testLocalAccount(t, s, "funnel@example.test")
	ctx := context.Background()
	if !registerTunnel(t, s, "funnel-test", id).Allowed {
		t.Fatal("registration denied")
	}
	count := func() int {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='tunnel'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(); n != 0 {
		t.Fatalf("before admission: %d", n)
	}
	req := &pb.TunnelAlertRequest{Operation: "up", AccountId: id, Tunnel: "funnel-test", Session: "fixture"}
	for i := 0; i < 2; i++ {
		if _, err := s.TunnelAlert(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(); n != 1 {
		t.Fatalf("after admission: %d", n)
	}
}
