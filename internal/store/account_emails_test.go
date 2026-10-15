package store

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

func TestAccountEmailConcurrentLinkCannotMergeOrSteal(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := NewAccountStore(db)
	first, err := s.FindOrCreateByEmails([]string{"first@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.FindOrCreateByEmails([]string{"second@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{first.ID, second.ID} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			_, err := s.MutateAccountEmail(context.Background(), id, "shared@example.com", "link")
			results <- err
		}(id)
	}
	close(start)
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrEmailOwned) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal(successes, conflicts)
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM accounts").Scan(&count); err != nil || count != 2 {
		t.Fatal("accounts merged", count, err)
	}
	for _, id := range []string{first.ID, second.ID} {
		a, err := s.GetByID(id)
		if err != nil || a.ID != id {
			t.Fatal(a, err)
		}
	}
}

// Guard the repository's production SQL as well as checking the supported operations below.
func TestAccountEmailProductionCodeNeverDeletesRows(t *testing.T) {
	deletion := regexp.MustCompile("(?i)\\b(delete\\s+from|replace\\s+into|drop\\s+table(?:\\s+if\\s+exists)?)\\s+[\"`\\[]?account_emails\\b")
	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if deletion.Match(source) {
			t.Errorf("production code can delete verified email rows: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAccountEmailActionsPreservePermanentBindings(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewAccountStore(db)
	owner, err := s.FindOrCreateByEmails([]string{"old@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.FindOrCreateByEmails([]string{"other@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	// A deletion, including one caused by a cascade, fails the actual operation.
	if _, err := db.Exec(`CREATE TRIGGER forbid_email_deletion BEFORE DELETE ON account_emails
        BEGIN SELECT RAISE(ABORT, 'verified email deleted'); END`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.MutateAccountEmail(ctx, owner.ID, "new@example.com", "link"); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"new@example.com", "old@example.com", "new@example.com"} {
		if _, err := s.MutateAccountEmail(ctx, owner.ID, email, "primary"); err != nil {
			t.Fatal(err)
		}
	}
	for _, email := range []string{"old@example.com", "new@example.com"} {
		for _, action := range []string{"remove", "", "unknown"} {
			if _, err := s.MutateAccountEmail(ctx, owner.ID, email, action); err == nil {
				t.Fatal("unsupported action accepted", action)
			}
		}
		if _, err := s.MutateAccountEmail(ctx, other.ID, email, "link"); !errors.Is(err, ErrEmailOwned) {
			t.Fatal("reassignment accepted", err)
		}
		account, err := s.FindOrCreateByEmails([]string{email}, "magic_link")
		if err != nil || account.ID != owner.ID {
			t.Fatal("login changed owners", account, err)
		}
		// The email column remains globally unique, even for a direct insertion.
		if _, err := db.Exec("INSERT INTO account_emails(account_id,email,verified_via,added_at) VALUES(?,?,'magic_link',1)", other.ID, email); err == nil {
			t.Fatal("duplicate email accepted", email)
		}
	}
	current, err := s.GetByID(owner.ID)
	if err != nil || len(current.Emails) != 2 || current.PrimaryEmail != "new@example.com" {
		t.Fatal(current, err)
	}
}
