package storage

import (
	"context"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
)

func newMagicLinkTestStorage(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatalf("init test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewLocalStorage(db)
}

func TestMarkMagicTokenUsed_FirstUseAndReplay(t *testing.T) {
	s := newMagicLinkTestStorage(t)
	ctx := context.Background()
	jti := "jti-replay-1"

	wasUnused, err := s.MarkMagicTokenUsed(ctx, jti, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("first use: unexpected error: %v", err)
	}
	if !wasUnused {
		t.Fatalf("first use: expected wasUnused=true, got false")
	}

	wasUnused, err = s.MarkMagicTokenUsed(ctx, jti, time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatalf("replay: unexpected error: %v", err)
	}
	if wasUnused {
		t.Fatalf("replay: expected wasUnused=false, got true")
	}
}

func TestMarkMagicTokenUsed_IndependentJTIs(t *testing.T) {
	s := newMagicLinkTestStorage(t)
	ctx := context.Background()

	for _, jti := range []string{"jti-ind-1", "jti-ind-2"} {
		wasUnused, err := s.MarkMagicTokenUsed(ctx, jti, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("first use of %q: unexpected error: %v", jti, err)
		}
		if !wasUnused {
			t.Fatalf("first use of %q: expected wasUnused=true, got false", jti)
		}
	}

	wasUnused, err := s.MarkMagicTokenUsed(ctx, "jti-ind-1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("replay of %q: unexpected error: %v", "jti-ind-1", err)
	}
	if wasUnused {
		t.Fatalf("replay of %q: expected wasUnused=false, got true", "jti-ind-1")
	}
}

func TestCheckMagicLinkRateLimit_AllowsUpToMax(t *testing.T) {
	s := newMagicLinkTestStorage(t)
	ctx := context.Background()
	email := "alice@example.com"

	for i, wantRemaining := range []int32{2, 1, 0} {
		allowed, remaining, _, err := s.CheckMagicLinkRateLimit(ctx, email)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("call %d: expected allowed=true, got false", i+1)
		}
		if remaining != wantRemaining {
			t.Errorf("call %d: expected remaining=%d, got %d", i+1, wantRemaining, remaining)
		}
	}
}

func TestCheckMagicLinkRateLimit_DeniesExcess(t *testing.T) {
	s := newMagicLinkTestStorage(t)
	ctx := context.Background()
	email := "bob@example.com"

	for i := 0; i < magicLinkRateMaxCount; i++ {
		allowed, _, _, err := s.CheckMagicLinkRateLimit(ctx, email)
		if err != nil {
			t.Fatalf("setup call %d: unexpected error: %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("setup call %d: expected allowed=true, got false", i+1)
		}
	}

	for i := 0; i < 2; i++ {
		allowed, remaining, _, err := s.CheckMagicLinkRateLimit(ctx, email)
		if err != nil {
			t.Fatalf("excess call %d: unexpected error: %v", i+1, err)
		}
		if allowed {
			t.Errorf("excess call %d: expected allowed=false, got true", i+1)
		}
		if remaining != 0 {
			t.Errorf("excess call %d: expected remaining=0, got %d", i+1, remaining)
		}
	}
}

func TestCheckMagicLinkRateLimit_IndependentEmails(t *testing.T) {
	s := newMagicLinkTestStorage(t)
	ctx := context.Background()
	emailA := "alice2@example.com"
	emailB := "bob2@example.com"

	for i := 0; i < magicLinkRateMaxCount; i++ {
		if _, _, _, err := s.CheckMagicLinkRateLimit(ctx, emailA); err != nil {
			t.Fatalf("emailA setup call %d: unexpected error: %v", i+1, err)
		}
	}

	allowed, _, _, err := s.CheckMagicLinkRateLimit(ctx, emailA)
	if err != nil {
		t.Fatalf("emailA excess call: unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("emailA: expected denied after budget exhausted, got allowed")
	}

	for i, wantRemaining := range []int32{2, 1, 0} {
		allowed, remaining, _, err := s.CheckMagicLinkRateLimit(ctx, emailB)
		if err != nil {
			t.Fatalf("emailB call %d: unexpected error: %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("emailB call %d: expected allowed=true, got false", i+1)
		}
		if remaining != wantRemaining {
			t.Errorf("emailB call %d: expected remaining=%d, got %d", i+1, wantRemaining, remaining)
		}
	}
}

func TestCheckMagicLinkRateLimit_ResetAtInFuture(t *testing.T) {
	s := newMagicLinkTestStorage(t)
	ctx := context.Background()
	email := "carol@example.com"

	now := time.Now()
	allowed, _, resetAt, err := s.CheckMagicLinkRateLimit(ctx, email)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected allowed=true, got false")
	}
	if resetAt.IsZero() {
		t.Fatalf("expected resetAt to be populated, got zero time")
	}
	if !resetAt.After(now) {
		t.Fatalf("expected resetAt in the future, got %v", resetAt)
	}

	expected := time.Now().Add(magicLinkRateWindow)
	diff := resetAt.Sub(expected)
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Second {
		t.Fatalf("expected resetAt ≈ now+%v, got %v (deviation %v)", magicLinkRateWindow, resetAt, diff)
	}
}
