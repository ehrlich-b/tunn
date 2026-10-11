package sshfront

import (
	"context"
	"database/sql"
	"testing"
)

func TestReviewPendingLinkCannotUndoRevocation(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	registry, err := NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pub := publicKey(t)
	key, err := registry.Add(ctx, "alice@example.com", pub)
	if err != nil {
		t.Fatal(err)
	}
	// This is an unused challenge issued before the device was revoked.
	token, err := registry.BeginLink(ctx, pub, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Remove(ctx, []string{"alice@example.com"}, key.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if owner, err := registry.Owner(ctx, key.Fingerprint); err != nil || owner != "" {
		t.Fatal(owner, err)
	}
	err = registry.CompleteLink(ctx, token)
	owner, lookupErr := registry.Owner(ctx, key.Fingerprint)
	if lookupErr != nil {
		t.Fatal(lookupErr)
	}
	if err == nil || owner != "" {
		t.Fatalf("pre-revocation pending link restored removed key: owner=%q completion=%v", owner, err)
	}
}
