package storage

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
)

// fixedClock is a concurrency-safe fake clock. It is injected through the
// LocalStorage.now field (the clock seam added to local.go; production default
// is time.Now) so magic-token TTL and magic-link rate-limit windows can be
// driven deterministically without sleeping on real wall-clock time.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFixedClock(t time.Time) *fixedClock { return &fixedClock{t: t} }

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestStorage builds a LocalStorage backed by an in-memory SQLite DB with an
// optional injected clock. Expiry is driven deterministically via
// cleanupExpiredJTIsOnce.
func newTestStorage(t *testing.T, clock *fixedClock) *LocalStorage {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatalf("store.InitForTest: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// SQLite :memory: databases belong to one connection, including concurrent redemptions.
	db.SetMaxOpenConns(1)

	s := &LocalStorage{
		deviceCodes:       store.NewDeviceCodeStore(db),
		accounts:          store.NewAccountStore(db),
		activeTunnels:     make(map[string]string),
		db:                db,
		magicLinkRequests: make(map[string][]time.Time),
	}
	if clock != nil {
		s.now = clock.Now
	}
	return s
}

func TestMagicTokenPersistenceWithInjectedClock(t *testing.T) {
	clock := newFixedClock(time.Unix(1_700_000_000, 0))
	first := newTestStorage(t, clock)
	second := NewLocalStorage(first.db)
	second.now = clock.Now
	ctx := context.Background()
	expiry := clock.Now().Add(5 * time.Minute)
	if unused, err := first.MarkMagicTokenUsed(ctx, "persistent-jti", expiry); err != nil || !unused {
		t.Fatalf("first redemption: unused=%v err=%v", unused, err)
	}
	if unused, err := second.MarkMagicTokenUsed(ctx, "persistent-jti", expiry); err != nil || unused {
		t.Fatalf("recreated storage accepted replay: unused=%v err=%v", unused, err)
	}
	clock.Advance(5 * time.Minute)
	if unused, err := second.MarkMagicTokenUsed(ctx, "expired-new-jti", expiry); err != nil || unused {
		t.Fatalf("expired claim accepted: unused=%v err=%v", unused, err)
	}
	if unused, err := second.MarkMagicTokenUsed(ctx, "persistent-jti", clock.Now().Add(time.Minute)); err != nil || !unused {
		t.Fatalf("expired record was not purged: unused=%v err=%v", unused, err)
	}
}

// TestMagicTokenLifecycle covers the issue -> redeem -> replay lifecycle of a
// magic-link token's JTI. MarkMagicTokenUsed returns wasUnused=true for the
// first redemption and false for every subsequent redemption of the same jti;
// that false signal IS the security property at the storage boundary. The
// caller (internal/host/magiclink.go verifyMagicLinkToken) maps it to the
// sentinel rejection error "token already used", so storage surfaces a replay
// as (wasUnused=false, err=nil) — distinguishable from an availability failure.
func TestMagicTokenLifecycle(t *testing.T) {
	clock := newFixedClock(time.Unix(1_700_000_000, 0))
	s := newTestStorage(t, clock)
	ctx := context.Background()

	const (
		jti1 = "magic-token-jti-1"
		jti2 = "magic-token-jti-2"
	)
	expiry := clock.Now().Add(5 * time.Minute)

	tests := []struct {
		name          string
		jti           string
		wantWasUnused bool
	}{
		{"redeem OK (first use of newly issued token)", jti1, true},
		{"REPLAY same token rejected", jti1, false},
		{"REPLAY again stays rejected", jti1, false},
		{"distinct token is independent", jti2, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wasUnused, err := s.MarkMagicTokenUsed(ctx, tt.jti, expiry)
			if err != nil {
				t.Fatalf("MarkMagicTokenUsed() error = %v, want nil", err)
			}
			if wasUnused != tt.wantWasUnused {
				t.Errorf("MarkMagicTokenUsed() wasUnused = %v, want %v", wasUnused, tt.wantWasUnused)
			}
		})
	}
}

// TestMagicTokenExpiry verifies the TTL behavior of magic-token replay
// protection. A token remains rejected while it is within its TTL; a token past
// its TTL is rejected (its JWT is expired) and its replay-protection state is
// purged from storage so it never outlives the token's TTL.
func TestMagicTokenExpiry(t *testing.T) {
	clock := newFixedClock(time.Unix(1_700_000_000, 0))
	s := newTestStorage(t, clock)
	ctx := context.Background()

	const (
		jti      = "magic-token-jti-expires"
		jtiLater = "magic-token-jti-live"
	)
	issuedAt := clock.Now()
	ttl := 5 * time.Minute
	expiry := issuedAt.Add(ttl)

	// Issue -> redeem within the TTL succeeds.
	if wasUnused, err := s.MarkMagicTokenUsed(ctx, jti, expiry); err != nil || !wasUnused {
		t.Fatalf("first redeem within TTL: wasUnused=%v err=%v, want (true,nil)", wasUnused, err)
	}
	// A replay while the token is still within its TTL is rejected.
	if wasUnused, err := s.MarkMagicTokenUsed(ctx, jti, expiry); err != nil || wasUnused {
		t.Fatalf("replay within TTL: wasUnused=%v err=%v, want (false,nil)", wasUnused, err)
	}
	// A separately issued token with a longer TTL is unaffected.
	if wasUnused, err := s.MarkMagicTokenUsed(ctx, jtiLater, issuedAt.Add(30*time.Minute)); err != nil || !wasUnused {
		t.Fatalf("redeem later-expiring token: wasUnused=%v err=%v, want (true,nil)", wasUnused, err)
	}

	// Advance past the first token's TTL and run the periodic cleanup pass.
	clock.Advance(ttl + time.Second)
	if err := s.cleanupExpiredJTIsOnce(); err != nil {
		t.Fatalf("cleanup expired replay records: %v", err)
	}

	// The token past its TTL is no longer tracked: its stale replay-protection
	// state has expired, so a freshly issued token using the same jti is usable.
	if wasUnused, err := s.MarkMagicTokenUsed(ctx, jti, clock.Now().Add(ttl)); err != nil || !wasUnused {
		t.Errorf("past-TTL token re-issue: wasUnused=%v err=%v, want (true,nil) (expired entry purged)", wasUnused, err)
	}
	// An unexpired token must survive the cleanup pass untouched.
	if wasUnused, err := s.MarkMagicTokenUsed(ctx, jtiLater, issuedAt.Add(30*time.Minute)); err != nil || wasUnused {
		t.Errorf("live token after cleanup: wasUnused=%v err=%v, want (false,nil) (must stay rejected)", wasUnused, err)
	}
}

// TestMagicLinkRateLimitBoundary verifies the per-email magic-link throttle:
// requests exactly at the limit pass, the request one past the limit is
// rejected, and the window resets once the interval has elapsed. resetAt is
// derived from the oldest request still inside the window.
func TestMagicLinkRateLimitBoundary(t *testing.T) {
	clock := newFixedClock(time.Unix(1_700_000_000, 0))
	s := newTestStorage(t, clock)
	ctx := context.Background()
	const email = "user@example.com"

	tests := []struct {
		name            string
		advance         time.Duration // cumulative clock advance applied before this call
		wantAllowed     bool
		wantRemaining   int32
		wantResetOffset time.Duration // expected resetAt relative to the initial time
	}{
		{"request 1 allowed", 0, true, 2, 5 * time.Minute},
		{"request 2 allowed", 0, true, 1, 5 * time.Minute},
		{"request 3 allowed (exactly at limit)", 0, true, 0, 5 * time.Minute},
		{"request 4 rejected (one past limit)", 0, false, 0, 5 * time.Minute},
		{"still rejected mid-window", time.Minute, false, 0, 5 * time.Minute},
		{"allowed again after window elapses", 4 * time.Minute, true, 2, 10 * time.Minute},
	}

	start := clock.Now()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock.Advance(tt.advance)

			allowed, remaining, resetAt, err := s.CheckMagicLinkRateLimit(ctx, email)
			if err != nil {
				t.Fatalf("CheckMagicLinkRateLimit() error = %v, want nil", err)
			}
			if allowed != tt.wantAllowed {
				t.Errorf("allowed = %v, want %v", allowed, tt.wantAllowed)
			}
			if remaining != tt.wantRemaining {
				t.Errorf("remaining = %d, want %d", remaining, tt.wantRemaining)
			}
			if wantReset := start.Add(tt.wantResetOffset); !resetAt.Equal(wantReset) {
				t.Errorf("resetAt = %v, want %v", resetAt, wantReset)
			}
		})
	}
}

// TestLocalStorageConcurrentAccess hammers the in-memory hot paths
// (magic-token replay tracking, magic-link rate limiting, and active-tunnel
// registration) with many goroutines. Run with -race to verify the mutex
// invariants: a shared token is redeemed by exactly one caller, an email's rate
// window grants exactly magicLinkRateMaxCount requests, and an account can
// register at most ProTunnelLimit tunnels.
func TestLocalStorageConcurrentAccess(t *testing.T) {
	clock := newFixedClock(time.Unix(1_700_000_000, 0))
	s := newTestStorage(t, clock)
	ctx := context.Background()
	expiry := clock.Now().Add(5 * time.Minute)

	t.Run("magic token replay is exactly-once", func(t *testing.T) {
		const sharedJTI = "shared-jti"
		const goroutines = 32
		var firstUse int64

		var wg sync.WaitGroup
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				wasUnused, err := s.MarkMagicTokenUsed(ctx, sharedJTI, expiry)
				if err != nil {
					t.Errorf("MarkMagicTokenUsed: %v", err)
					return
				}
				if wasUnused {
					atomic.AddInt64(&firstUse, 1)
				}
			}()
		}
		wg.Wait()

		if got := atomic.LoadInt64(&firstUse); got != 1 {
			t.Errorf("shared token redeemed %d times, want exactly once", got)
		}

		// Distinct jtis must all be redeemable once.
		const distinct = 32
		for i := 0; i < distinct; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				jti := fmt.Sprintf("distinct-jti-%d", n)
				wasUnused, err := s.MarkMagicTokenUsed(ctx, jti, expiry)
				if err != nil || !wasUnused {
					t.Errorf("distinct jti %s: wasUnused=%v err=%v, want (true,nil)", jti, wasUnused, err)
				}
			}(i)
		}
		wg.Wait()
	})

	t.Run("magic link rate limit is enforced under contention", func(t *testing.T) {
		const email = "conc@example.com"
		const attempts = 64
		var allowedCount int64

		var wg sync.WaitGroup
		for i := 0; i < attempts; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				allowed, _, _, err := s.CheckMagicLinkRateLimit(ctx, email)
				if err != nil {
					t.Errorf("CheckMagicLinkRateLimit: %v", err)
					return
				}
				if allowed {
					atomic.AddInt64(&allowedCount, 1)
				}
			}()
		}
		wg.Wait()

		if got := atomic.LoadInt64(&allowedCount); got != int64(magicLinkRateMaxCount) {
			t.Errorf("allowed requests = %d, want exactly %d", got, magicLinkRateMaxCount)
		}
	})

	t.Run("tunnel registration enforces the plan limit under contention", func(t *testing.T) {
		acc, err := s.accounts.FindOrCreateByEmails([]string{"conc-tunnel@example.com"}, "github")
		if err != nil {
			t.Fatalf("FindOrCreateByEmails: %v", err)
		}
		if err := s.accounts.UpdatePlan(acc.ID, "pro"); err != nil {
			t.Fatalf("UpdatePlan: %v", err)
		}

		const registrations = ProTunnelLimit + 5
		var registered int64

		var wg sync.WaitGroup
		for i := 0; i < registrations; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				reg, err := s.RegisterTunnel(ctx, fmt.Sprintf("tunnel-%d", n), acc.ID, "node-1")
				if err != nil {
					t.Errorf("RegisterTunnel: %v", err)
					return
				}
				if reg.Allowed {
					atomic.AddInt64(&registered, 1)
				} else if reg.Reason == "" {
					t.Errorf("rejected registration for tunnel-%d has empty reason", n)
				}
			}(i)
		}
		wg.Wait()

		if got := atomic.LoadInt64(&registered); got != int64(ProTunnelLimit) {
			t.Errorf("registered tunnels = %d, want exactly %d", got, ProTunnelLimit)
		}

		// Concurrently unregister everything; the account count must return to 0.
		for i := 0; i < registrations; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				if err := s.UnregisterTunnel(ctx, fmt.Sprintf("tunnel-%d", n)); err != nil {
					t.Errorf("UnregisterTunnel: %v", err)
				}
			}(i)
		}
		wg.Wait()

		count, err := s.GetTunnelCount(ctx, acc.ID)
		if err != nil {
			t.Fatalf("GetTunnelCount: %v", err)
		}
		if count != 0 {
			t.Errorf("tunnel count after unregister = %d, want 0", count)
		}
	})
}

// TestTunnelRegistrationLimits checks the free/pro tunnel-capacity boundaries
// and duplicate-ID rejection derived from limits.go and RegisterTunnel.
func TestTunnelRegistrationLimits(t *testing.T) {
	s := newTestStorage(t, nil)
	ctx := context.Background()

	newAccount := func(t *testing.T, email, plan string) string {
		t.Helper()
		acc, err := s.accounts.FindOrCreateByEmails([]string{email}, "github")
		if err != nil {
			t.Fatalf("FindOrCreateByEmails: %v", err)
		}
		if plan == "pro" {
			if err := s.accounts.UpdatePlan(acc.ID, "pro"); err != nil {
				t.Fatalf("UpdatePlan: %v", err)
			}
		}
		return acc.ID
	}

	t.Run("free plan allows FreeTunnelLimit tunnels", func(t *testing.T) {
		acc := newAccount(t, "free@example.com", "free")
		for i := 0; i < FreeTunnelLimit; i++ {
			reg, err := s.RegisterTunnel(ctx, fmt.Sprintf("free-%d", i), acc, "node-1")
			if err != nil || !reg.Allowed {
				t.Fatalf("registration %d: allowed=%v err=%v (%v)", i, reg.Allowed, err, reg.Reason)
			}
		}
		reg, err := s.RegisterTunnel(ctx, "free-extra", acc, "node-1")
		if err != nil {
			t.Fatalf("RegisterTunnel: %v", err)
		}
		if reg.Allowed || reg.Reason != "tunnel limit reached" {
			t.Errorf("got allowed=%v reason=%q, want rejected with %q", reg.Allowed, reg.Reason, "tunnel limit reached")
		}
	})

	t.Run("pro plan allows ProTunnelLimit tunnels", func(t *testing.T) {
		acc := newAccount(t, "pro@example.com", "pro")
		for i := 0; i < ProTunnelLimit; i++ {
			reg, err := s.RegisterTunnel(ctx, fmt.Sprintf("pro-%d", i), acc, "node-1")
			if err != nil || !reg.Allowed {
				t.Fatalf("registration %d: allowed=%v err=%v", i, reg.Allowed, err)
			}
		}
	})

	t.Run("duplicate tunnel ID is rejected", func(t *testing.T) {
		acc := newAccount(t, "dup@example.com", "free")
		reg, err := s.RegisterTunnel(ctx, "dup-tunnel", acc, "node-1")
		if err != nil || !reg.Allowed {
			t.Fatalf("first registration: allowed=%v err=%v", reg.Allowed, err)
		}
		reg, err = s.RegisterTunnel(ctx, "dup-tunnel", acc, "node-1")
		if err != nil {
			t.Fatalf("RegisterTunnel: %v", err)
		}
		if reg.Allowed || reg.Reason != "tunnel ID already in use" {
			t.Errorf("got allowed=%v reason=%q, want rejected with %q", reg.Allowed, reg.Reason, "tunnel ID already in use")
		}
	})
}
