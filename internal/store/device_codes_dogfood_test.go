package store

import (
	"testing"
	"time"
)

func TestDogfoodDeviceCodeLifetimeAndReuse(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewDeviceCodeStore(db)
	start := time.Now()
	code, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	if lifetime := code.ExpiresAt.Sub(start); lifetime < 10*time.Minute || lifetime > 10*time.Minute+time.Second {
		t.Fatalf("device lifetime = %s, want 10 minutes", lifetime)
	}
	// A phone approval after the old three-minute window must still succeed.
	if _, err := db.Exec("UPDATE device_codes SET expires_at = ? WHERE code = ?", time.Now().Add(6*time.Minute).Unix(), code.Code); err != nil {
		t.Fatal(err)
	}
	if !s.Authorize(code.Code, "owner@example.test") {
		t.Fatal("code was unavailable after old expiry window")
	}
	if s.Authorize(code.Code, "other@example.test") {
		t.Fatal("used code was authorized again")
	}
	if got := s.Get(code.Code); got == nil || got.Email != "owner@example.test" {
		t.Fatalf("authorized identity changed: %+v", got)
	}
	if _, err := db.Exec("UPDATE device_codes SET expires_at = ? WHERE code = ?", time.Now().Add(-time.Second).Unix(), code.Code); err != nil {
		t.Fatal(err)
	}
	if s.Get(code.Code) != nil || s.GetByUserCode(code.UserCode) != nil || s.Authorize(code.Code, "owner@example.test") {
		t.Fatal("expired code still usable")
	}
}
