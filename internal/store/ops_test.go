package store

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func opsDBChild(t *testing.T, mode, path string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOpsDBStartupChild$")
	cmd.Env = append(os.Environ(), "TUNN_OPS_DB_HELPER="+mode, "TUNN_OPS_DB_FIXTURE="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("database child %s: %v\n%s", mode, err, output)
	}
}

func TestOpsDBStartupChild(t *testing.T) {
	mode := os.Getenv("TUNN_OPS_DB_HELPER")
	if mode == "" {
		return
	}
	path := os.Getenv("TUNN_OPS_DB_FIXTURE")
	if mode == "failure" {
		first, firstErr := InitDB(path)
		if firstErr == nil {
			t.Fatal("expected invalid volume path to fail")
		}
		second, secondErr := InitDB(path)
		if secondErr == nil || secondErr.Error() != firstErr.Error() {
			t.Fatalf("startup failure forgotten on retry: %v / %v", firstErr, secondErr)
		}
		if first != nil || second != nil || DB() != nil {
			t.Fatal("failed startup published a database handle")
		}
		return
	}
	if mode == "concurrent" {
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make(chan *sql.DB, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				db, err := InitDB(path)
				if err != nil {
					t.Error(err)
				}
				results <- db
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		for db := range results {
			if db == nil || db != DB() {
				t.Fatal("concurrent initialization returned different handles")
			}
		}
		if err := Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if mode == "wal" {
		db, err := InitDB(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("PRAGMA wal_autocheckpoint=0; INSERT INTO accounts VALUES ('wal-owner','wal@example.com','free',1)"); err != nil {
			t.Fatal(err)
		}
		// Leave the handle open: process exit models recovery of committed WAL.
		return
	}
	t.Fatal("unknown child mode")
}

func TestOpsDBInitializationFailureRemainsFailure(t *testing.T) {
	for _, failure := range []string{"parent file", "database directory", "corrupt database", "incompatible schema"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "tunn.db")
			switch failure {
			case "parent file":
				if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(path, "child.db")
			case "database directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "corrupt database":
				if err := os.WriteFile(path, []byte("fixture that is not a SQLite database"), 0600); err != nil {
					t.Fatal(err)
				}
			case "incompatible schema":
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("CREATE TABLE accounts (incompatible TEXT); INSERT INTO accounts VALUES ('retained')"); err != nil {
					t.Fatal(err)
				}
				_ = db.Close()
			}
			opsDBChild(t, "failure", path)
			if failure == "corrupt database" {
				contents, err := os.ReadFile(path)
				if err != nil || string(contents) != "fixture that is not a SQLite database" {
					t.Fatal("startup overwrote corrupt volume evidence")
				}
			}
			if failure == "incompatible schema" {
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = db.Close() }()
				var retained string
				if err := db.QueryRow("SELECT incompatible FROM accounts").Scan(&retained); err != nil || retained != "retained" {
					t.Fatal("migration failure replaced existing data")
				}
			}
		})
	}
}

func TestOpsDBConcurrentInitialization(t *testing.T) {
	opsDBChild(t, "concurrent", filepath.Join(t.TempDir(), "tunn.db"))
}

func TestOpsDBRestartRecoversCommittedWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunn.db")
	opsDBChild(t, "wal", path)
	if info, err := os.Stat(path + "-wal"); err != nil || info.Size() == 0 {
		t.Fatal("fixture did not leave committed WAL")
	}
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	account, err := NewAccountStore(db).GetByID("wal-owner")
	if err != nil || account.PrimaryEmail != "wal@example.com" {
		t.Fatalf("WAL recovery lost account: %v %v", account, err)
	}
}

func TestOpsDBDiskRestartPreservesIdentityAndReservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunn.db")
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	accounts := NewAccountStore(db)
	account, err := accounts.FindOrCreateByEmails([]string{"alice@example.com", "alice@work.example"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpdatePlan(account.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if err := accounts.ReserveSubdomain(account.ID, "retained"); err != nil {
		t.Fatal(err)
	}
	codes := NewDeviceCodeStore(db)
	code, err := codes.Create()
	if err != nil || !codes.Authorize(code.Code, "alice@example.com") {
		t.Fatal("create/authorize device code:", err)
	}
	if _, err := db.Exec("INSERT INTO used_magic_tokens VALUES ('consumed-fixture',?)", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		db, err = OpenLocal(path)
		if err != nil {
			t.Fatal(err)
		}
		accounts = NewAccountStore(db)
		got, err := accounts.GetByID(account.ID)
		if err != nil || got.Plan != "pro" || len(got.Emails) != 2 {
			t.Fatalf("restart lost account: %+v %v", got, err)
		}
		owner, err := accounts.GetSubdomainOwner("retained")
		if err != nil || owner != account.ID {
			t.Fatal("restart lost reservation", err)
		}
		gotCode := NewDeviceCodeStore(db).Get(code.Code)
		if gotCode == nil || !gotCode.Authorized || gotCode.Email != "alice@example.com" {
			t.Fatal("restart lost authorized device code")
		}
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM used_magic_tokens WHERE jti='consumed-fixture'").Scan(&count); err != nil || count != 1 {
			t.Fatal("restart lost consumed magic link", err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpsDBLegacyMigrationIsRepeatable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunn.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE accounts (id TEXT PRIMARY KEY, primary_email TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'free', created_at INTEGER NOT NULL);
INSERT INTO accounts VALUES ('legacy','legacy@example.com','pro',42);`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	for i := 0; i < 2; i++ {
		db, err = OpenLocal(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := NewAccountStore(db).GetByID("legacy")
		if err != nil || got.Plan != "pro" || got.CreatedAt.Unix() != 42 {
			t.Fatal("migration changed legacy identity", err)
		}
		var check string
		if err := db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
			t.Fatal("migration produced invalid database", err)
		}
		_ = db.Close()
	}
}
