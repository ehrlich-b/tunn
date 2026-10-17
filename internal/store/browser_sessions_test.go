package store

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestBrowserSessionEpochMigrationPersistenceAndMerge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { db.Close() }()
	accounts := NewAccountStore(db)
	a, err := accounts.FindOrCreateByEmails([]string{"first@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	b, err := accounts.FindOrCreateByEmails([]string{"second@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if a.BrowserSessionEpoch != "" || b.BrowserSessionEpoch != "" {
		t.Fatal("unexpected initial epoch")
	}
	ctx := context.Background()
	// Concurrent copies of one logout rotate the epoch exactly once.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := accounts.RevokeBrowserSessions(ctx, a.ID, ""); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	revoked, err := accounts.GetByID(a.ID)
	if err != nil || revoked.BrowserSessionEpoch == "" {
		t.Fatalf("epoch not rotated: %+v %v", revoked, err)
	}
	epoch := revoked.BrowserSessionEpoch
	if err := accounts.RevokeBrowserSessions(ctx, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	accounts = NewAccountStore(db)
	restarted, err := accounts.GetByID(a.ID)
	if err != nil || restarted.BrowserSessionEpoch != epoch {
		t.Fatalf("restart changed epoch: %+v %v", restarted, err)
	}
	for i := 0; i < 2; i++ {
		if err := MigrateBrowserSessions(db); err != nil {
			t.Fatal(err)
		}
	}
	untouched, err := accounts.GetByEmail(b.PrimaryEmail)
	if err != nil || untouched.BrowserSessionEpoch != "" {
		t.Fatal("other account changed")
	}
	merged, err := accounts.FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if merged.BrowserSessionEpoch == "" || merged.BrowserSessionEpoch == epoch {
		t.Fatal("merge could revive a revoked cookie")
	}
	for _, id := range []string{a.ID, b.ID} {
		current, err := accounts.GetByID(id)
		if err != nil || current.BrowserSessionEpoch != merged.BrowserSessionEpoch {
			t.Fatal("merged epoch mismatch", err)
		}
	}
	// Revocation through an obsolete UUID must affect the canonical account.
	if err := accounts.RevokeBrowserSessions(ctx, a.ID, merged.BrowserSessionEpoch); err != nil {
		t.Fatal(err)
	}
	current, err := accounts.GetByID(b.ID)
	if err != nil || current.BrowserSessionEpoch == merged.BrowserSessionEpoch {
		t.Fatal("alias logout did not revoke the canonical account")
	}
}

// The upgrade gate supplies a real database created by the previous binary.
func TestBrowserSessionUpgradeDatabase(t *testing.T) {
	path := os.Getenv("TUNN_BROWSER_SESSION_UPGRADE_DB")
	if path == "" {
		t.Skip("upgrade gate supplies previous-version database")
	}
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accounts := NewAccountStore(db)
	account, err := accounts.GetByEmail("upgrade@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if account.BrowserSessionEpoch != "" {
		t.Fatal("legacy session was not preserved before logout")
	}
	if err := accounts.RevokeBrowserSessions(context.Background(), account.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := MigrateBrowserSessions(db); err != nil {
		t.Fatal(err)
	}
	account, err = accounts.GetByID(account.ID)
	if err != nil || account.BrowserSessionEpoch == "" {
		t.Fatalf("upgraded revocation did not persist: %+v %v", account, err)
	}
	t.Log("previous-version database migrated, legacy account retained, logout persisted, migration rerun succeeded")
}
