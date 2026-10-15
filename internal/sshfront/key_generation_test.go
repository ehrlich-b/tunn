package sshfront

import (
	"context"
	"github.com/ehrlich-b/tunn/internal/store"
	"sync"
	"testing"
	"time"
)

func TestSSHKeyLegacyChallengesInvalidated(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, email := range []string{"alice@example.com", "mallory@example.com"} {
		if _, err := store.NewAccountStore(db).FindOrCreateByEmails([]string{email}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	_, err = db.Exec(`CREATE TABLE ssh_keys(fingerprint TEXT PRIMARY KEY,public_key TEXT NOT NULL,owner_email TEXT NOT NULL);
 CREATE TABLE ssh_key_links(digest TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,public_key TEXT NOT NULL,email TEXT NOT NULL,expires INTEGER NOT NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	pub := publicKey(t)
	key, err := ParseKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO ssh_key_links VALUES(?,?,?,?,?)", linkDigest("old-authority"), key.Fingerprint, pub, "alice@example.com", time.Now().Add(time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteLink(context.Background(), "old-authority"); err == nil {
		t.Fatal("legacy unbound challenge survived migration")
	}
	token, err := r.BeginLink(context.Background(), pub, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteLink(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	// Migration must be idempotent and keep newly issued bound challenges.
	token, err = r.BeginLink(context.Background(), pub, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.CompleteLink(context.Background(), token); err != nil {
		t.Fatal(err)
	}
}

func TestSSHKeyConcurrentCompletionAndRemoval(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, email := range []string{"alice@example.com", "mallory@example.com"} {
		if _, err := store.NewAccountStore(db).FindOrCreateByEmails([]string{email}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pub := publicKey(t)
	for attempt := 0; attempt < 16; attempt++ {
		key, err := r.Add(ctx, "alice@example.com", pub)
		if err != nil {
			t.Fatal(err)
		}
		token, err := r.BeginLink(ctx, pub, "alice@example.com")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		removed := make(chan error, 1)
		go func() {
			defer wg.Done()
			<-start
			removed <- r.Remove(ctx, keyTestAccountID(t, db, "alice@example.com"), key.Fingerprint)
		}()
		go func() { defer wg.Done(); <-start; _ = r.CompleteLink(ctx, token) }()
		close(start)
		wg.Wait()
		if err := <-removed; err != nil {
			t.Fatal(err)
		}
		if owner, err := r.Owner(ctx, key.Fingerprint); err != nil || owner != "" {
			t.Fatal("concurrent old confirmation resurrected key", owner, err)
		}
		if err := r.CompleteLink(ctx, token); err == nil {
			t.Fatal("old challenge retained authority")
		}
	}
}

func TestSSHOldSessionCannotReinsertRemovedKey(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, email := range []string{"alice@example.com", "mallory@example.com"} {
		if _, err := store.NewAccountStore(db).FindOrCreateByEmails([]string{email}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pub := publicKey(t)
	key, err := r.Add(ctx, "alice@example.com", pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ConfirmSessionKey(ctx, keyTestAccountID(t, db, "alice@example.com"), pub); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove(ctx, keyTestAccountID(t, db, "alice@example.com"), key.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ConfirmSessionKey(ctx, keyTestAccountID(t, db, "alice@example.com"), pub); err == nil {
		t.Fatal("old session undid revocation")
	}
	if owner, err := r.Owner(ctx, key.Fingerprint); err != nil || owner != "" {
		t.Fatal(owner, err)
	}
}
