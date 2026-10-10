package storage

import (
	"context"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
)

func newTestLocalStorage(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewLocalStorage(db)
}

func registerTunnel(t *testing.T, ls *LocalStorage, tunnelID, accountID string) *TunnelRegistration {
	t.Helper()
	reg, err := ls.RegisterTunnel(context.Background(), tunnelID, accountID, "localhost")
	if err != nil {
		t.Fatalf("RegisterTunnel(%q) returned error: %v", tunnelID, err)
	}
	return reg
}

func TestRegisterTunnelFreeLimit(t *testing.T) {
	ls := newTestLocalStorage(t)
	const accountID = "acct-free-limit"
	ctx := context.Background()

	// 1. Register up to the free limit.
	expected := []int32{1, 2, 3}
	for i, want := range expected {
		tunnelID := "free-tunnel-" + string(rune('a'+i))
		reg, err := ls.RegisterTunnel(ctx, tunnelID, accountID, "localhost")
		if err != nil {
			t.Fatalf("RegisterTunnel(%q) returned error: %v", tunnelID, err)
		}
		if !reg.Allowed {
			t.Fatalf("RegisterTunnel(%q) unexpected rejection: %q", tunnelID, reg.Reason)
		}
		if reg.CurrentCount != want {
			t.Errorf("RegisterTunnel(%q) CurrentCount = %d, want %d", tunnelID, reg.CurrentCount, want)
		}
		if reg.MaxAllowed != FreeTunnelLimit {
			t.Errorf("RegisterTunnel(%q) MaxAllowed = %d, want %d", tunnelID, reg.MaxAllowed, FreeTunnelLimit)
		}
	}

	// 2. The 4th registration for the same account is rejected.
	reg := registerTunnel(t, ls, "free-tunnel-d", accountID)
	if reg.Allowed {
		t.Error("expected 4th registration to be rejected")
	}
	if reg.Reason != "tunnel limit reached" {
		t.Errorf("Reason = %q, want %q", reg.Reason, "tunnel limit reached")
	}
	if reg.CurrentCount != 3 {
		t.Errorf("CurrentCount = %d, want 3", reg.CurrentCount)
	}
	if reg.MaxAllowed != FreeTunnelLimit {
		t.Errorf("MaxAllowed = %d, want %d", reg.MaxAllowed, FreeTunnelLimit)
	}
}

func TestRegisterTunnelDuplicateID(t *testing.T) {
	ls := newTestLocalStorage(t)
	ctx := context.Background()

	const accountA = "acct-dup-a"
	const accountB = "acct-dup-b"

	reg := registerTunnel(t, ls, "shared-tunnel", accountA)
	if !reg.Allowed {
		t.Fatalf("expected first registration to be allowed, got %q", reg.Reason)
	}

	// 3. Same tunnel ID from a different account must be rejected.
	dup, err := ls.RegisterTunnel(ctx, "shared-tunnel", accountB, "localhost")
	if err != nil {
		t.Fatalf("RegisterTunnel returned error: %v", err)
	}
	if dup.Allowed {
		t.Error("expected duplicate tunnel ID to be rejected")
	}
	if dup.Reason != "tunnel ID already in use" {
		t.Errorf("Reason = %q, want %q", dup.Reason, "tunnel ID already in use")
	}
	// The duplicate path should not populate these fields.
	if dup.CurrentCount != 0 {
		t.Errorf("CurrentCount = %d, want 0", dup.CurrentCount)
	}
	if dup.MaxAllowed != 0 {
		t.Errorf("MaxAllowed = %d, want 0", dup.MaxAllowed)
	}
}

func TestUnregisterTunnel(t *testing.T) {
	ls := newTestLocalStorage(t)
	const accountID = "acct-unregister"
	ctx := context.Background()

	// 1. Set up three tunnels.
	tunnelIDs := []string{"tun-a", "tun-b", "tun-c"}
	for _, id := range tunnelIDs {
		reg := registerTunnel(t, ls, id, accountID)
		if !reg.Allowed {
			t.Fatalf("expected registration of %q to be allowed, got %q", id, reg.Reason)
		}
	}

	// 4. Unregister one, count drops 3 -> 2, then re-register a new ID.
	if err := ls.UnregisterTunnel(ctx, "tun-b"); err != nil {
		t.Fatalf("UnregisterTunnel returned error: %v", err)
	}
	count, err := ls.GetTunnelCount(ctx, accountID)
	if err != nil {
		t.Fatalf("GetTunnelCount returned error: %v", err)
	}
	if count != 2 {
		t.Errorf("GetTunnelCount after unregister = %d, want 2", count)
	}

	reg := registerTunnel(t, ls, "tun-d", accountID)
	if !reg.Allowed {
		t.Fatalf("expected re-registration to be allowed, got %q", reg.Reason)
	}
	if reg.CurrentCount != 3 {
		t.Errorf("CurrentCount after re-register = %d, want 3", reg.CurrentCount)
	}

	// 5. Unregister an ID that was never registered: no error, no side effects.
	if err := ls.UnregisterTunnel(ctx, "never-registered"); err != nil {
		t.Errorf("UnregisterTunnel on unknown ID returned error: %v", err)
	}
	count, err = ls.GetTunnelCount(ctx, accountID)
	if err != nil {
		t.Fatalf("GetTunnelCount returned error: %v", err)
	}
	if count != 3 {
		t.Errorf("GetTunnelCount = %d, want 3 after no-op unregister", count)
	}
}

func TestTunnelLimitsArePerAccount(t *testing.T) {
	ls := newTestLocalStorage(t)
	const accountA = "acct-a"
	const accountB = "acct-b"
	ctx := context.Background()

	// 6. Fill account A's free limit.
	for i := 0; i < FreeTunnelLimit; i++ {
		id := "a-tunnel-" + string(rune('a'+i))
		reg := registerTunnel(t, ls, id, accountA)
		if !reg.Allowed {
			t.Fatalf("expected registration of %q to be allowed, got %q", id, reg.Reason)
		}
	}

	// Account A is now at its limit.
	reg := registerTunnel(t, ls, "a-tunnel-overflow", accountA)
	if reg.Allowed {
		t.Error("expected account A to be at its limit")
	}

	// Fresh account B can still register in the same instance.
	regB := registerTunnel(t, ls, "b-tunnel-a", accountB)
	if !regB.Allowed {
		t.Fatalf("expected account B registration to be allowed, got %q", regB.Reason)
	}

	countA, err := ls.GetTunnelCount(ctx, accountA)
	if err != nil {
		t.Fatalf("GetTunnelCount(A) returned error: %v", err)
	}
	countB, err := ls.GetTunnelCount(ctx, accountB)
	if err != nil {
		t.Fatalf("GetTunnelCount(B) returned error: %v", err)
	}
	if countA != FreeTunnelLimit {
		t.Errorf("GetTunnelCount(A) = %d, want %d", countA, FreeTunnelLimit)
	}
	if countB != 1 {
		t.Errorf("GetTunnelCount(B) = %d, want 1", countB)
	}
}

func TestGetTunnelCountZero(t *testing.T) {
	ls := newTestLocalStorage(t)
	ctx := context.Background()

	// 7. Account with no tunnels returns 0, not an error.
	count, err := ls.GetTunnelCount(ctx, "acct-empty")
	if err != nil {
		t.Fatalf("GetTunnelCount returned error: %v", err)
	}
	if count != 0 {
		t.Errorf("GetTunnelCount = %d, want 0", count)
	}
}
