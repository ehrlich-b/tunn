package store_test

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
)

func accountCorrectnessDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.OpenLocal(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT OR IGNORE INTO ops_fixture VALUES(1,'disposable-local')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestAccountsConcurrentFirstLoginUsesOneBucket(t *testing.T) {
	db := accountCorrectnessDB(t)
	accounts := store.NewAccountStore(db)
	const logins = 16
	start := make(chan struct{})
	results := make(chan *store.Account, logins)
	var wg sync.WaitGroup
	for i := 0; i < logins; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			account, err := accounts.FindOrCreateByEmails([]string{"Owner@Example.invalid"}, "github")
			if err != nil {
				t.Errorf("first login: %v", err)
				return
			}
			results <- account
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var id string
	for account := range results {
		if id == "" {
			id = account.ID
		}
		if account.ID != id || len(account.Emails) != 1 || account.Emails[0].Email != "owner@example.invalid" {
			t.Errorf("login returned another or empty bucket: %+v; want ID %s", account, id)
		}
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("concurrent login created %d accounts, want 1", count)
	}
}

func TestAccountsEmailWriteFailureRollsBackBucket(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing_%t", existing), func(t *testing.T) {
			db := accountCorrectnessDB(t)
			accounts := store.NewAccountStore(db)
			if existing {
				if _, err := accounts.FindOrCreateByEmails([]string{"owner@example.invalid"}, "magic_link"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(`CREATE TRIGGER fail_email BEFORE INSERT ON account_emails
WHEN NEW.email='last@example.invalid' BEGIN SELECT RAISE(ABORT,'fixture email write failure'); END`); err != nil {
				t.Fatal(err)
			}
			if _, err := accounts.FindOrCreateByEmails([]string{"owner@example.invalid", "second@example.invalid", "last@example.invalid"}, "github"); err == nil {
				t.Fatal("email write failure was ignored")
			}
			var accountCount, emailCount int
			if err := db.QueryRow("SELECT count(*) FROM accounts").Scan(&accountCount); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow("SELECT count(*) FROM account_emails").Scan(&emailCount); err != nil {
				t.Fatal(err)
			}
			want := 0
			if existing {
				want = 1
			}
			if accountCount != want || emailCount != want {
				t.Fatalf("failed login left partial identity: accounts=%d emails=%d, want %d each", accountCount, emailCount, want)
			}
		})
	}
}
