package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Account represents a user account (email bucket)
type Account struct {
	ID           string
	PrimaryEmail string
	Plan         string // "free" or "pro"
	CreatedAt    time.Time
	Emails       []AccountEmail
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
	if len(emails) == 0 {
		return nil, sql.ErrNoRows
	}

	// Normalize emails
	for i := range emails {
		emails[i] = strings.ToLower(strings.TrimSpace(emails[i]))
	}

	// Find all accounts that own any of these emails
	placeholders := make([]string, len(emails))
	args := make([]interface{}, len(emails))
	for i, email := range emails {
		placeholders[i] = "?"
		args[i] = email
	}

	query := `SELECT DISTINCT a.id, a.primary_email, a.plan, a.created_at
	          FROM accounts a
	          JOIN account_emails ae ON a.id = ae.account_id
	          WHERE ae.email IN (` + strings.Join(placeholders, ",") + `)`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*Account
	for rows.Next() {
		var acc Account
		var createdAtUnix int64
		if err := rows.Scan(&acc.ID, &acc.PrimaryEmail, &acc.Plan, &createdAtUnix); err != nil {
			return nil, err
		}
		acc.CreatedAt = time.Unix(createdAtUnix, 0)
		accounts = append(accounts, &acc)
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
		_, err := s.db.Exec(
			"INSERT INTO accounts (id, primary_email, plan, created_at) VALUES (?, ?, ?, ?)",
			account.ID, account.PrimaryEmail, account.Plan, account.CreatedAt.Unix(),
		)
		if err != nil {
			return nil, err
		}

	case 1:
		// Use existing account
		account = accounts[0]

	default:
		// Merge multiple accounts into one
		account, err = s.mergeAccounts(accounts)
		if err != nil {
			return nil, err
		}
	}

	// Add any new emails to the account
	for _, email := range emails {
		// Try to insert, ignore if already exists
		s.db.Exec(
			"INSERT OR IGNORE INTO account_emails (account_id, email, verified_via, added_at) VALUES (?, ?, ?, ?)",
			account.ID, email, verifiedVia, time.Now().Unix(),
		)
	}

	// Load all emails for the account
	account.Emails, err = s.getAccountEmails(account.ID)
	if err != nil {
		return nil, err
	}

	return account, nil
}

// GetByEmail finds an account by any email in its bucket
func (s *AccountStore) GetByEmail(email string) (*Account, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	var account Account
	var createdAtUnix int64

	err := s.db.QueryRow(`
		SELECT a.id, a.primary_email, a.plan, a.created_at
		FROM accounts a
		JOIN account_emails ae ON a.id = ae.account_id
		WHERE ae.email = ?
	`, email).Scan(&account.ID, &account.PrimaryEmail, &account.Plan, &createdAtUnix)
	if err != nil {
		return nil, err
	}

	account.CreatedAt = time.Unix(createdAtUnix, 0)
	account.Emails, err = s.getAccountEmails(account.ID)
	if err != nil {
		return nil, err
	}

	return &account, nil
}

// GetEmailBucket returns all emails associated with an account containing the given email
func (s *AccountStore) GetEmailBucket(email string) ([]string, error) {
	account, err := s.GetByEmail(email)
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

// UpdatePlan updates an account's plan
func (s *AccountStore) UpdatePlan(accountID, plan string) error {
	_, err := s.db.Exec("UPDATE accounts SET plan = ? WHERE id = ?", plan, accountID)
	return err
}

// mergeAccounts merges multiple accounts into one, keeping the best plan
func (s *AccountStore) mergeAccounts(accounts []*Account) (*Account, error) {
	if len(accounts) == 0 {
		return nil, sql.ErrNoRows
	}

	// Find the account with the best plan (pro > free)
	var primary *Account
	for _, acc := range accounts {
		if primary == nil || acc.Plan == "pro" {
			primary = acc
		}
	}

	// Move all emails from other accounts to the primary account
	for _, acc := range accounts {
		if acc.ID != primary.ID {
			// Update emails to point to primary account
			_, err := s.db.Exec(
				"UPDATE account_emails SET account_id = ? WHERE account_id = ?",
				primary.ID, acc.ID,
			)
			if err != nil {
				return nil, err
			}

			// Delete the merged account
			_, err = s.db.Exec("DELETE FROM accounts WHERE id = ?", acc.ID)
			if err != nil {
				return nil, err
			}
		}
	}

	return primary, nil
}

// getAccountEmails returns all emails for an account
func (s *AccountStore) getAccountEmails(accountID string) ([]AccountEmail, error) {
	rows, err := s.db.Query(
		"SELECT email, verified_via, added_at FROM account_emails WHERE account_id = ?",
		accountID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
	return emails, nil
}

// MaxReservedSubdomains is the maximum number of reserved subdomains per Pro account
const MaxReservedSubdomains = 4

// ReservedSubdomain represents a subdomain reserved by an account
type ReservedSubdomain struct {
	Subdomain string
	AccountID string
	CreatedAt time.Time
}

// ReserveSubdomain reserves a subdomain for an account (Pro feature)
// Returns an error if:
// - Account is not Pro
// - Account already has 4 reserved subdomains
// - Subdomain is already reserved by another account
func (s *AccountStore) ReserveSubdomain(accountID, subdomain string) error {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))

	// Check if account is Pro
	var plan string
	err := s.db.QueryRow("SELECT plan FROM accounts WHERE id = ?", accountID).Scan(&plan)
	if err != nil {
		return err
	}
	if plan != "pro" {
		return fmt.Errorf("subdomain reservations require a Pro plan")
	}

	// Check current count
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM reserved_subdomains WHERE account_id = ?", accountID).Scan(&count)
	if err != nil {
		return err
	}
	if count >= MaxReservedSubdomains {
		return fmt.Errorf("maximum of %d reserved subdomains reached", MaxReservedSubdomains)
	}

	// Try to insert (will fail if already exists)
	_, err = s.db.Exec(
		"INSERT INTO reserved_subdomains (subdomain, account_id, created_at) VALUES (?, ?, ?)",
		subdomain, accountID, time.Now().Unix(),
	)
	if err != nil {
		// Check if it's already reserved
		var existingAccountID string
		checkErr := s.db.QueryRow("SELECT account_id FROM reserved_subdomains WHERE subdomain = ?", subdomain).Scan(&existingAccountID)
		if checkErr == nil {
			if existingAccountID == accountID {
				return nil // Already reserved by this account, that's fine
			}
			return fmt.Errorf("subdomain '%s' is already reserved by another user", subdomain)
		}
		return err
	}

	return nil
}

// GetSubdomainOwner returns the account ID that owns a subdomain, or empty string if not reserved
func (s *AccountStore) GetSubdomainOwner(subdomain string) (string, error) {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))

	var accountID string
	err := s.db.QueryRow("SELECT account_id FROM reserved_subdomains WHERE subdomain = ?", subdomain).Scan(&accountID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return accountID, nil
}

// GetReservedSubdomains returns all subdomains reserved by an account
func (s *AccountStore) GetReservedSubdomains(accountID string) ([]ReservedSubdomain, error) {
	rows, err := s.db.Query(
		"SELECT subdomain, account_id, created_at FROM reserved_subdomains WHERE account_id = ?",
		accountID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
	return subdomains, nil
}

// ReleaseSubdomain releases a reserved subdomain
func (s *AccountStore) ReleaseSubdomain(accountID, subdomain string) error {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))

	result, err := s.db.Exec(
		"DELETE FROM reserved_subdomains WHERE subdomain = ? AND account_id = ?",
		subdomain, accountID,
	)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("subdomain '%s' not found or not owned by this account", subdomain)
	}
	return nil
}
