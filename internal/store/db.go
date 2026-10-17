package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

var (
	globalDB   *sql.DB
	globalOnce sync.Once
	globalErr  error
	globalMu   sync.RWMutex
)

// InitDB initializes the SQLite database at the given path.
// Only login nodes should call this. Returns the database connection.
// If path is empty, uses default path based on environment.
func InitDB(path string) (*sql.DB, error) {
	globalOnce.Do(func() {
		globalMu.Lock()
		defer globalMu.Unlock()
		dbPath := path
		if dbPath == "" {
			// Default: ~/.tunn/tunn.db for local, /data/tunn.db for Fly.io
			if _, err := os.Stat("/data"); err == nil {
				dbPath = "/data/tunn.db"
			} else {
				home, _ := os.UserHomeDir()
				dbPath = filepath.Join(home, ".tunn", "tunn.db")
			}
		}

		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
			globalErr = fmt.Errorf("failed to create db directory: %w", err)
			return
		}

		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			globalErr = fmt.Errorf("failed to open database: %w", err)
			return
		}
		db.SetMaxOpenConns(1)
		defer func() {
			if globalErr != nil {
				_ = db.Close()
			}
		}()

		// Enable WAL mode for better concurrency
		if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
			globalErr = fmt.Errorf("failed to set WAL mode: %w", err)
			return
		}

		// Initialize schema
		if err := initSchema(db); err != nil {
			globalErr = fmt.Errorf("failed to init schema: %w", err)
			return
		}
		globalDB = db
	})
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalDB, globalErr
}

// DB returns the global database connection, or nil if not initialized.
// Non-login nodes will have nil here - they proxy DB operations to login node.
func DB() *sql.DB {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalDB
}

// InitForTest initializes a disposable database for testing. Closing the database
// removes its temporary directory.
// File backing preserves the schema and fixtures when cancellation causes
// database/sql to discard and replace a connection.
func InitForTest() (*sql.DB, error) {
	dir, err := os.MkdirTemp("", "tunn-test-db-")
	if err != nil {
		return nil, err
	}
	initialized := false
	defer func() {
		if !initialized {
			_ = os.RemoveAll(dir)
		}
	}()
	path := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(filepath.Join(dir, "test.db"))
	dsn := "file:" + path + "?_pragma=journal_mode(MEMORY)&_pragma=synchronous(OFF)&_pragma=busy_timeout(5000)"
	registeredDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	drv := registeredDB.Driver()
	_ = registeredDB.Close()
	testDB := sql.OpenDB(&testDBConnector{drv: drv, dsn: dsn, dir: dir})
	if err := initSchema(testDB); err != nil {
		_ = testDB.Close()
		return nil, err
	}
	if _, err := testDB.Exec(`CREATE TABLE ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO ops_fixture VALUES(1,'disposable-local')`); err != nil {
		_ = testDB.Close()
		return nil, err
	}
	initialized = true
	return testDB, nil
}

type testDBConnector struct {
	drv driver.Driver
	dsn string
	dir string
}

func (c *testDBConnector) Connect(context.Context) (driver.Conn, error) {
	return c.drv.Open(c.dsn)
}

func (c *testDBConnector) Driver() driver.Driver { return c.drv }

func (c *testDBConnector) Close() error {
	_ = os.RemoveAll(c.dir)
	return nil
}

func initSchema(db *sql.DB) error {
	schema := `
	-- Device codes for CLI login flow
	CREATE TABLE IF NOT EXISTS device_codes (
		code TEXT PRIMARY KEY,
		user_code TEXT UNIQUE NOT NULL,
		expires_at INTEGER NOT NULL,
		authorized INTEGER NOT NULL DEFAULT 0,
		email TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
	CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);

	-- Accounts (email buckets)
	CREATE TABLE IF NOT EXISTS accounts (
		id TEXT PRIMARY KEY,
		primary_email TEXT NOT NULL,
		plan TEXT NOT NULL DEFAULT 'free',
		created_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_accounts_primary_email ON accounts(primary_email);

	-- Keep live publishers and delayed accounting tied to the surviving UUID.
	CREATE TABLE IF NOT EXISTS account_merges (
		old_id TEXT PRIMARY KEY,
		account_id TEXT NOT NULL,
		FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_account_merges_account_id ON account_merges(account_id);

	-- Provider identities stay bound to their subject, independently of email.
	CREATE TABLE IF NOT EXISTS account_provider_identities (
	 issuer TEXT NOT NULL, subject TEXT NOT NULL, account_id TEXT NOT NULL,
	 email TEXT NOT NULL, PRIMARY KEY(issuer,subject),
	 FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE);

	-- Account emails (many-to-one with accounts)
	CREATE TABLE IF NOT EXISTS account_emails (
		account_id TEXT NOT NULL,
		email TEXT PRIMARY KEY,
		verified_via TEXT NOT NULL,
		added_at INTEGER NOT NULL,
		FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_account_emails_account_id ON account_emails(account_id);

	-- Bandwidth usage tracking
	CREATE TABLE IF NOT EXISTS account_usage (
		account_id TEXT NOT NULL,
		month TEXT NOT NULL,
		bytes_used INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (account_id, month),
		FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	);

	-- Reserved subdomains (Pro feature: up to 4 per account)
	CREATE TABLE IF NOT EXISTS reserved_subdomains (
		subdomain TEXT PRIMARY KEY,
		account_id TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_reserved_subdomains_account_id ON reserved_subdomains(account_id);

	-- Consumed magic links survive login-node restarts until token expiry.
	CREATE TABLE IF NOT EXISTS used_magic_tokens (
		jti TEXT PRIMARY KEY,
		expires_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_used_magic_tokens_expires_at ON used_magic_tokens(expires_at);
	`
	_, err := db.Exec(schema)
	if err != nil {
		return err
	}
	if err := MigrateDevicePurpose(db); err != nil {
		return err
	}
	if err := MigrateBrowserSessions(db); err != nil {
		return err
	}
	return MigrateOperations(db)
}

// OpenLocal opens an explicitly selected database without process-global state.
// Operators and disposable fixtures use this instead of the host's singleton.
func OpenLocal(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;"); err == nil {
		err = initSchema(db)
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// Close closes the database connection
func Close() error {
	globalMu.RLock()
	defer globalMu.RUnlock()
	if globalDB != nil {
		return globalDB.Close()
	}
	return nil
}
