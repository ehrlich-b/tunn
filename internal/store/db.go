package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

var (
	globalDB   *sql.DB
	globalOnce sync.Once
	globalErr  error
)

// InitDB initializes the SQLite database at the given path.
// Only login nodes should call this. Returns the database connection.
// If path is empty, uses default path based on environment.
func InitDB(path string) (*sql.DB, error) {
	var initErr error
	globalOnce.Do(func() {
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
			initErr = fmt.Errorf("failed to create db directory: %w", err)
			return
		}

		globalDB, initErr = sql.Open("sqlite", dbPath)
		if initErr != nil {
			initErr = fmt.Errorf("failed to open database: %w", initErr)
			return
		}

		// Enable WAL mode for better concurrency
		if _, err := globalDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
			initErr = fmt.Errorf("failed to set WAL mode: %w", err)
			return
		}

		// Initialize schema
		if err := initSchema(globalDB); err != nil {
			initErr = fmt.Errorf("failed to init schema: %w", err)
			return
		}
	})
	globalErr = initErr
	return globalDB, globalErr
}

// DB returns the global database connection, or nil if not initialized.
// Non-login nodes will have nil here - they proxy DB operations to login node.
func DB() *sql.DB {
	return globalDB
}

// InitForTest initializes an in-memory database for testing
func InitForTest() (*sql.DB, error) {
	testDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	if err := initSchema(testDB); err != nil {
		return nil, err
	}
	return testDB, nil
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
	`
	_, err := db.Exec(schema)
	return err
}

// Close closes the database connection
func Close() error {
	if globalDB != nil {
		return globalDB.Close()
	}
	return nil
}
