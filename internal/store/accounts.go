package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/google/uuid"
)

// Account represents a user account (email bucket)
type Account struct {
	BrowserSessionEpoch string
	BillingNotice       string
	BillingState        string
	OperationalState    string
	OperationalVersion  int64
	ID                  string
	PrimaryEmail        string
	Plan                string // "free" or "pro"
	CreatedAt           time.Time
	Emails              []AccountEmail
}

// AccountEmail represents an email in an account bucket
type AccountEmail struct {
	Email       string
	VerifiedVia string // "github", "magic_link"
	AddedAt     time.Time
}

// AccountStore manages accounts in SQLite
type AccountStore struct {
	db *sql.DB
}

// NewAccountStore creates a new SQLite-backed account store
func NewAccountStore(db *sql.DB) *AccountStore {
	return &AccountStore{db: db}
}

// FindOrCreateByEmails finds an existing account containing any of the emails,
// or creates a new account. Handles account merging when emails span multiple accounts.
func (s *AccountStore) FindOrCreateByEmails(emails []string, verifiedVia string) (*Account, error) {
	return s.FindOrCreateByEmailsContext(context.Background(), emails, verifiedVia)
}

func (s *AccountStore) FindOrCreateByEmailsContext(ctx context.Context, emails []string, verifiedVia string) (*Account, error) {
	if len(emails) == 0 {
		return nil, sql.ErrNoRows
	}

	// Normalize emails (Unicode NFKC + lowercase to prevent homograph attacks)
	for i := range emails {
		emails[i] = common.NormalizeEmail(emails[i])
	}
	// Keep lookup, creation, merges and alias attachment in one transaction.
	// A concurrent login must not return an account whose email insert lost to
	// another login, and a failed alias write must roll back the whole bucket.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	account, err := s.findOrCreateByEmailsTx(ctx, tx, emails, verifiedVia)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return account, nil
}

// findOrCreateByEmailsTx lets provider binding and email attachment commit together.
func (s *AccountStore) findOrCreateByEmailsTx(ctx context.Context, tx *sql.Tx, emails []string, verifiedVia string) (*Account, error) {

	// Find all accounts that own any of these emails
	placeholders := make([]string, len(emails))
	args := make([]interface{}, len(emails))
	for i, email := range emails {
		placeholders[i] = "?"
		args[i] = email
	}

	query := `SELECT DISTINCT a.id, a.primary_email, a.plan, a.created_at, COALESCE((SELECT epoch FROM browser_session_epochs WHERE account_id=a.id),'')
	          FROM accounts a
	          JOIN account_emails ae ON a.id = ae.account_id
	          WHERE ae.email IN (` + strings.Join(placeholders, ",") + `)`

	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var accounts []*Account
	for rows.Next() {
		var acc Account
		var createdAtUnix int64
		if err := rows.Scan(&acc.ID, &acc.PrimaryEmail, &acc.Plan, &createdAtUnix, &acc.BrowserSessionEpoch); err != nil {
			return nil, err
		}
		acc.CreatedAt = time.Unix(createdAtUnix, 0)
		accounts = append(accounts, &acc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	var account *Account

	switch len(accounts) {
	case 0:
		// Create new account
		account = &Account{
			ID:           uuid.New().String(),
			PrimaryEmail: emails[0],
			Plan:         "free",
			CreatedAt:    time.Now(),
		}
		_, err := tx.Exec(
			"INSERT INTO accounts (id, primary_email, plan, created_at) VALUES (?, ?, ?, ?)",
			account.ID, account.PrimaryEmail, account.Plan, account.CreatedAt.Unix(),
		)
		if err != nil {
			return nil, err
		}

		RecordFunnel(ctx, tx, "signup", account.ID)

	case 1:
		// Use existing account
		account = accounts[0]

	default:
		// Merge multiple accounts into one
		account, err = s.mergeAccounts(tx, accounts)
		if err != nil {
			return nil, err
		}
	}

	// Add any new emails to the account
	for _, email := range emails {
		// Try to insert, ignore if already exists
		_, err := tx.Exec(
			"INSERT OR IGNORE INTO account_emails (account_id, email, verified_via, added_at) VALUES (?, ?, ?, ?)",
			account.ID, email, verifiedVia, time.Now().Unix(),
		)
		if err != nil {
			return nil, fmt.Errorf("add account email: %w", err)
		}
	}

	// Load all emails for the account
	account.Emails, err = getAccountEmails(tx, account.ID)
	if err != nil {
		return nil, err
	}

	status, err := readAccountStatus(context.Background(), tx, account.ID)
	if err != nil {
		return nil, err
	}
	account.OperationalState, account.OperationalVersion = status.State, status.Version
	account.Plan, account.BillingState, err = billingAccountState(context.Background(), tx, account.ID)
	if err == nil {
		account.BillingNotice, err = billingNotice(context.Background(), tx, account.ID)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.QueryRow("SELECT COALESCE((SELECT epoch FROM browser_session_epochs WHERE account_id=?),'')", account.ID).Scan(&account.BrowserSessionEpoch); err != nil {
		return nil, err
	}
	return account, nil
}

// GetByEmail finds an account by any email in its bucket.
// Uses NFKC normalization to prevent Unicode homograph attacks.
func (s *AccountStore) GetByEmail(email string) (*Account, error) {
	return s.GetByEmailContext(context.Background(), email)
}

func (s *AccountStore) GetByEmailContext(ctx context.Context, email string) (*Account, error) {
	email = common.NormalizeEmail(email)

	var account Account
	var createdAtUnix int64

	err := s.db.QueryRowContext(ctx, `
		SELECT a.id, a.primary_email, a.plan, a.created_at, COALESCE((SELECT epoch FROM browser_session_epochs WHERE account_id=a.id),'')
		FROM accounts a
		JOIN account_emails ae ON a.id = ae.account_id
		WHERE ae.email = ?
	`, email).Scan(&account.ID, &account.PrimaryEmail, &account.Plan, &createdAtUnix, &account.BrowserSessionEpoch)
	if err != nil {
		return nil, err
	}

	account.CreatedAt = time.Unix(createdAtUnix, 0)
	account.Emails, err = getAccountEmailsContext(ctx, s.db, account.ID)
	if err != nil {
		return nil, err
	}

	if err = s.loadOperationalStateContext(ctx, &account); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &account, nil
}

// GetEmailBucket returns all emails associated with an account containing the given email
func (s *AccountStore) GetEmailBucket(email string) ([]string, error) {
	return s.GetEmailBucketContext(context.Background(), email)
}

func (s *AccountStore) GetEmailBucketContext(ctx context.Context, email string) ([]string, error) {
	account, err := s.GetByEmailContext(ctx, email)
	if err != nil {
		// If no account found, return just the email itself
		if err == sql.ErrNoRows {
			return []string{email}, nil
		}
		return nil, err
	}

	emails := make([]string, len(account.Emails))
	for i, ae := range account.Emails {
		emails[i] = ae.Email
	}
	return emails, nil
}

// UpdatePlan changes a synthetic subscription in a marked disposable fixture.
func (s *AccountStore) UpdatePlan(accountID, plan string) error {
	return s.updateFixturePlan(accountID, plan)
}

// mergeAccounts combines verified identities and reduces their billing state.
func (s *AccountStore) mergeAccounts(tx *sql.Tx, accounts []*Account) (*Account, error) {
	if len(accounts) == 0 {
		return nil, sql.ErrNoRows
	}

	// Prefer a paid survivor to preserve existing identity selection.
	var primary *Account
	for _, acc := range accounts {
		if primary == nil || acc.Plan == "pro" {
			primary = acc
		}
	}

	// Move account-owned endpoints and reservations with the verified email
	// bucket. Without this, a later multi-email login would orphan stable names.
	var hostTables int
	if err := tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='host_machines'").Scan(&hostTables); err != nil {
		return nil, err
	}
	for _, acc := range accounts {
		if acc.ID == primary.ID {
			continue
		}
		if _, err := tx.Exec("UPDATE account_emails SET account_id = ? WHERE account_id = ?", primary.ID, acc.ID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec("UPDATE reserved_subdomains SET account_id = ? WHERE account_id = ?", primary.ID, acc.ID); err != nil {
			return nil, err
		}
		if err := mergeTunnelAlerts(tx, acc.ID, primary.ID); err != nil {
			return nil, err
		}
		if hostTables != 0 {
			if _, err := tx.Exec(`INSERT INTO host_machines(account_id, machine, last_seen)
SELECT ?, machine, last_seen FROM host_machines WHERE account_id=?
ON CONFLICT(account_id, machine) DO UPDATE SET last_seen=MAX(host_machines.last_seen, excluded.last_seen)`, primary.ID, acc.ID); err != nil {
				return nil, err
			}
			if _, err := tx.Exec("UPDATE host_endpoints SET account_id=? WHERE account_id=?", primary.ID, acc.ID); err != nil {
				return nil, err
			}
			if _, err := tx.Exec("DELETE FROM host_machines WHERE account_id=?", acc.ID); err != nil {
				return nil, err
			}
		}
		var domainTables int
		if err := tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='custom_domains'").Scan(&domainTables); err != nil {
			return nil, err
		}
		if domainTables != 0 {
			if _, err := tx.Exec("UPDATE custom_domains SET owner=? WHERE owner=?", primary.ID, acc.ID); err != nil {
				return nil, err
			}
		}
		if err := mergeAccountAccounting(tx, acc.ID, primary.ID); err != nil {
			return nil, err
		}
		if err := mergeBrowserSessions(tx, acc.ID, primary.ID); err != nil {
			return nil, err
		}
		if err := mergeAccountOperations(tx, acc.ID, primary.ID); err != nil {
			return nil, err
		}
		moveFunnelIdentity(context.Background(), tx, acc.ID, primary.ID, false)
		// Flatten prior merges so every obsolete UUID resolves in one lookup.
		if _, err := tx.Exec("UPDATE account_merges SET account_id=? WHERE account_id=?", primary.ID, acc.ID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec("INSERT INTO account_merges(old_id,account_id) VALUES(?,?)", acc.ID, primary.ID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec("DELETE FROM accounts WHERE id=?", acc.ID); err != nil {
			return nil, err
		}
	}
	plan, checkout, err := billingAccountState(context.Background(), tx, primary.ID)
	if err != nil {
		return nil, err
	}
	primary.Plan, primary.BillingState = plan, checkout
	return primary, nil
}

// getAccountEmails returns all emails for an account
func (s *AccountStore) getAccountEmails(accountID string) ([]AccountEmail, error) {
	return getAccountEmails(s.db, accountID)
}

func getAccountEmails(q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, accountID string) ([]AccountEmail, error) {
	return getAccountEmailsContext(context.Background(), q, accountID)
}

func getAccountEmailsContext(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, accountID string) ([]AccountEmail, error) {
	rows, err := q.QueryContext(ctx,
		"SELECT email, verified_via, added_at FROM account_emails WHERE account_id = ?",
		accountID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var emails []AccountEmail
	for rows.Next() {
		var ae AccountEmail
		var addedAtUnix int64
		if err := rows.Scan(&ae.Email, &ae.VerifiedVia, &addedAtUnix); err != nil {
			return nil, err
		}
		ae.AddedAt = time.Unix(addedAtUnix, 0)
		emails = append(emails, ae)
	}
	return emails, rows.Err()
}

// MaxReservedSubdomains is the maximum number of reserved subdomains per Pro account
const MaxReservedSubdomains = 10

// FreeReservedSubdomains is the Free account reservation allowance.
const FreeReservedSubdomains = 1

func ReservedSubdomainLimit(plan string) int {
	if plan == "pro" {
		return MaxReservedSubdomains
	}
	return FreeReservedSubdomains
}

// ReservedSubdomain represents a subdomain reserved by an account
type ReservedSubdomain struct {
	Subdomain string
	AccountID string
	CreatedAt time.Time
}

// ReserveSubdomain reserves a subdomain within the account plan allowance.
// Returns an error if:
// - Account has reached its plan reservation allowance
// - Subdomain is already reserved by another account
func (s *AccountStore) ReserveSubdomain(accountID, subdomain string) error {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	status, err := readAccountStatus(context.Background(), tx, accountID)
	if err != nil {
		return err
	}
	if status.State != "active" {
		return ErrSuspended
	}
	accountID = status.AccountID

	// Read the effective account plan
	var plan string
	plan, _, err = billingAccountState(context.Background(), tx, accountID)
	if err != nil {
		return err
	}
	limit := ReservedSubdomainLimit(plan)
	// Retrying an owned reservation consumes no additional allowance, even
	// when the account has reached its limit.
	var existingAccountID string
	err = tx.QueryRow("SELECT account_id FROM reserved_subdomains WHERE subdomain = ?", subdomain).Scan(&existingAccountID)
	if err == nil {
		if existingAccountID == accountID {
			if plan == "free" {
				var claimed bool
				if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM free_reservation_claims WHERE subdomain=?)", subdomain).Scan(&claimed); err != nil {
					return err
				}
				if !claimed {
					var count int
					if err := tx.QueryRow("SELECT COUNT(*) FROM reserved_subdomains WHERE account_id=?", accountID).Scan(&count); err != nil {
						return err
					}
					if count > limit {
						return fmt.Errorf("maximum of %d reserved subdomains reached", limit)
					}
					if _, err := tx.Exec("INSERT INTO free_reservation_claims VALUES(?)", subdomain); err != nil {
						return err
					}
				}
			}
			return tx.Commit()
		}
		return fmt.Errorf("subdomain '%s' is already reserved by another user", subdomain)
	}
	if err != sql.ErrNoRows {
		return err
	}

	if err := CheckNewSharedReservation(subdomain); err != nil {
		return err
	}

	// Check current count
	var count int
	err = tx.QueryRow("SELECT COUNT(*) FROM reserved_subdomains WHERE account_id = ?", accountID).Scan(&count)
	if err != nil {
		return err
	}
	if count >= limit {
		return fmt.Errorf("maximum of %d reserved subdomains reached", limit)
	}

	// Try to insert (will fail if already exists)
	_, err = tx.Exec(
		"INSERT INTO reserved_subdomains (subdomain, account_id, created_at) VALUES (?, ?, ?)",
		subdomain, accountID, time.Now().Unix(),
	)
	if err != nil {
		return err
	}

	if plan == "free" {
		if _, err := tx.Exec("INSERT INTO free_reservation_claims VALUES(?)", subdomain); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetSubdomainOwner returns the account ID that owns a subdomain, or empty string if not reserved
func (s *AccountStore) GetSubdomainOwner(subdomain string) (string, error) {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))

	var accountID string
	err := s.db.QueryRow(`SELECT account_id FROM reserved_subdomains WHERE subdomain=?`, subdomain).Scan(&accountID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	plan, _, err := billingAccountState(context.Background(), s.db, accountID)
	if err != nil {
		return "", err
	}
	// A forged/stale Pro cache must not retain paid reservations without a
	// verified entitlement. Genuine Free reservations use the Free cache.
	var cachedPlan string
	if err := s.db.QueryRow("SELECT plan FROM accounts WHERE id=?", accountID).Scan(&cachedPlan); err != nil {
		return "", err
	}
	if plan == "free" && cachedPlan != "free" {
		return "", nil
	}
	if plan == "free" {
		var claimed bool
		if err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM free_reservation_claims WHERE subdomain=?)", subdomain).Scan(&claimed); err != nil {
			return "", err
		}
		if !claimed {
			return "", nil
		}
	}
	return accountID, nil
}

// GetReservedSubdomains returns all subdomains reserved by an account
func (s *AccountStore) GetReservedSubdomains(accountID string) ([]ReservedSubdomain, error) {
	rows, err := s.db.Query(
		`SELECT subdomain, account_id, created_at FROM reserved_subdomains
		 WHERE account_id = COALESCE((SELECT account_id FROM account_merges WHERE old_id = ?), ?)`,
		accountID, accountID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var subdomains []ReservedSubdomain
	for rows.Next() {
		var rs ReservedSubdomain
		var createdAtUnix int64
		if err := rows.Scan(&rs.Subdomain, &rs.AccountID, &createdAtUnix); err != nil {
			return nil, err
		}
		rs.CreatedAt = time.Unix(createdAtUnix, 0)
		subdomains = append(subdomains, rs)
	}
	return subdomains, rows.Err()
}

// ReleaseSubdomain releases a reserved subdomain
func (s *AccountStore) ReleaseSubdomain(accountID, subdomain string) error {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err = releaseSubdomain(context.Background(), tx, accountID, subdomain); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordUsage adds bytes to an account's monthly usage
func (s *AccountStore) RecordUsage(accountID string, bytes int64) error {
	month := time.Now().UTC().Format("2006-01")

	result, err := s.db.Exec(`
		INSERT INTO account_usage (account_id, month, bytes_used)
		SELECT id, ?, ? FROM accounts
		WHERE id = COALESCE((SELECT account_id FROM account_merges WHERE old_id = ?), ?)
		ON CONFLICT(account_id, month) DO UPDATE SET bytes_used = bytes_used + excluded.bytes_used
	`, month, bytes, accountID, accountID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetMonthlyUsage returns the bytes used by an account in the current month
func (s *AccountStore) GetMonthlyUsage(accountID string) (int64, error) {
	month := time.Now().UTC().Format("2006-01")

	var bytesUsed int64
	err := s.db.QueryRow(
		`SELECT COALESCE(u.bytes_used, 0)
		 FROM accounts a LEFT JOIN account_usage u ON u.account_id = a.id AND u.month = ?
		 WHERE a.id = COALESCE((SELECT account_id FROM account_merges WHERE old_id = ?), ?)`,
		month, accountID, accountID,
	).Scan(&bytesUsed)
	if err != nil {
		return 0, err
	}
	return bytesUsed, nil
}

// GetByID retrieves an account by its ID
func (s *AccountStore) GetByID(accountID string) (*Account, error) {
	return s.GetByIDContext(context.Background(), accountID)
}

func (s *AccountStore) GetByIDContext(ctx context.Context, accountID string) (*Account, error) {
	var account Account
	var createdAtUnix int64

	err := s.db.QueryRowContext(ctx, `
		SELECT id, primary_email, plan, created_at, COALESCE((SELECT epoch FROM browser_session_epochs WHERE account_id=accounts.id),'')
		FROM accounts
		WHERE id = COALESCE((SELECT account_id FROM account_merges WHERE old_id = ?), ?)
	`, accountID, accountID).Scan(&account.ID, &account.PrimaryEmail, &account.Plan, &createdAtUnix, &account.BrowserSessionEpoch)
	if err != nil {
		return nil, err
	}

	account.CreatedAt = time.Unix(createdAtUnix, 0)
	account.Emails, err = getAccountEmailsContext(ctx, s.db, account.ID)
	if err != nil {
		return nil, err
	}

	if err = s.loadOperationalStateContext(ctx, &account); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &account, nil
}

func (s *AccountStore) loadOperationalState(account *Account) error {
	return s.loadOperationalStateContext(context.Background(), account)
}

func (s *AccountStore) loadOperationalStateContext(ctx context.Context, account *Account) error {
	status, err := NewOperationsStore(s.db, nil).LookupAccountStatus(ctx, account.ID)
	if err != nil {
		return err
	}
	account.OperationalState, account.OperationalVersion = status.State, status.Version
	account.Plan, account.BillingState, err = billingAccountState(context.Background(), s.db, account.ID)
	if err == nil {
		account.BillingNotice, err = billingNotice(context.Background(), s.db, account.ID)
	}
	return err
}
