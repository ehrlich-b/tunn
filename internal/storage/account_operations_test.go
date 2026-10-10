package storage

import (
	"context"
	"testing"
	"time"
)

func TestAccountOperationsMailLimiterClockAndStorageFailure(t *testing.T) {
	s := newMagicLinkTestStorage(t)
	now := time.Date(2026, 10, 10, 16, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		allowed, _, _, err := s.CheckMagicLinkRateLimit(ctx, "Owner@Example.Invalid")
		if err != nil || !allowed {
			t.Fatal(allowed, err)
		}
	}
	if allowed, _, _, err := s.CheckMagicLinkRateLimit(ctx, "owner@example.invalid"); err != nil || allowed {
		t.Fatal(allowed, err)
	}
	now = now.Add(5 * time.Minute)
	if allowed, remaining, _, err := s.CheckMagicLinkRateLimit(ctx, "owner@example.invalid"); err != nil || !allowed || remaining != 2 {
		t.Fatal(allowed, remaining, err)
	}
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	if allowed, _, _, err := s.CheckMagicLinkRateLimit(ctx, "another@example.invalid"); err == nil || allowed {
		t.Fatal("closed storage allowed mail", allowed, err)
	}
}
