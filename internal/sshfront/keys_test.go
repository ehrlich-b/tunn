package sshfront

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"github.com/ehrlich-b/tunn/internal/store"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
)

func publicKey(t *testing.T) string {
	t.Helper()
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}
func TestKeyLinkOwnershipAndReplay(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
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
	key, _ := ParseKey(pub)
	token, err := r.BeginLink(ctx, pub, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := r.Owner(ctx, key.Fingerprint); err != nil || owner != "" {
		t.Fatalf("unverified key owner=%q, %v", owner, err)
	}
	if email, err := r.LinkEmail(ctx, token); err != nil || email != "alice@example.com" {
		t.Fatalf("email=%q, %v", email, err)
	}
	if err := r.CompleteLink(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteLink(ctx, token); err == nil {
		t.Fatal("replayed key link")
	}
	if _, err := r.Add(ctx, "mallory@example.com", pub); err == nil {
		t.Fatal("key stolen by other account")
	}
	if err := r.Remove(ctx, keyTestAccountID(t, db, "mallory@example.com"), key.Fingerprint); err == nil {
		t.Fatal("other account removed key")
	}
	keys, err := r.List(ctx, keyTestAccountID(t, db, "alice@example.com"))
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	if err := r.Remove(ctx, keyTestAccountID(t, db, "alice@example.com"), key.Fingerprint); err != nil {
		t.Fatal(err)
	}
	token, err = r.BeginLink(ctx, pub, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE ssh_key_links SET expires=?", time.Now().Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteLink(ctx, token); err == nil {
		t.Fatal("expired key link accepted")
	}
	for _, pub := range []string{pub + "\n" + pub, "command=\"sh\" " + pub, "not a key", strings.Repeat("x", 17000)} {
		if _, err := ParseKey(pub); err == nil {
			t.Fatal("malformed or multi-key input accepted")
		}
	}
}

func TestOptionsGrammarAndAnonymousAdmission(t *testing.T) {
	args, err := UsernameArgs("qr+allow+bob@x.com")
	if err != nil || strings.Join(args, " ") != "--qr --allow bob@x.com" {
		t.Fatalf("username=%v %v", args, err)
	}
	args, err = SplitCommand(`-- --allow "bob@x.com,alice@y.com" --expire '2h' --name demo`)
	if err != nil || len(args) != 7 {
		t.Fatalf("command=%v %v", args, err)
	}
	if _, err := SplitCommand(`--name 'unfinished`); err == nil {
		t.Fatal("unfinished quote")
	}
	s := &Server{budgets: map[string]*budget{}}
	id := Identity{Fingerprint: "one", IP: "127.0.0.1"}
	release, err := s.acquire(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.acquire(id); err == nil {
		t.Fatal("second anonymous tunnel")
	}
	if !s.charge(id, int(AnonymousBytes)) || s.charge(id, 1) {
		t.Fatal("anonymous byte budget not enforced")
	}
	release()
	release()
	if _, err := s.acquire(id); err == nil {
		t.Fatal("reconnect reset anonymous budget")
	}
	if _, err := s.acquire(Identity{Fingerprint: "two", IP: id.IP}); err == nil {
		t.Fatal("new key reset IP budget")
	}
}

func keyTestAccountID(t *testing.T, db *sql.DB, email string) string {
	t.Helper()
	a, err := store.NewAccountStore(db).GetByEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}
