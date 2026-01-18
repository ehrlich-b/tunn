package storage

import (
	"context"
	"database/sql"
	"sync"

	"github.com/ehrlich-b/tunn/internal/store"
)

// LocalStorage implements Storage using local SQLite stores.
// Used by the login node for direct database access.
type LocalStorage struct {
	deviceCodes *store.DeviceCodeStore
	accounts    *store.AccountStore

	// Active tunnels tracked in memory
	// Maps tunnel_id -> account_id
	activeTunnels   map[string]string
	activeTunnelsMu sync.RWMutex
}

// NewLocalStorage creates a new LocalStorage backed by SQLite.
func NewLocalStorage(db *sql.DB) *LocalStorage {
	return &LocalStorage{
		deviceCodes:   store.NewDeviceCodeStore(db),
		accounts:      store.NewAccountStore(db),
		activeTunnels: make(map[string]string),
	}
}

// Available returns true since local storage is always available on login node.
func (s *LocalStorage) Available() bool {
	return true
}

// CreateDeviceCode creates a new device code for CLI login.
func (s *LocalStorage) CreateDeviceCode(ctx context.Context) (*DeviceCode, error) {
	code, err := s.deviceCodes.Create()
	if err != nil {
		return nil, err
	}
	return &DeviceCode{
		Code:       code.Code,
		UserCode:   code.UserCode,
		ExpiresAt:  code.ExpiresAt,
		Interval:   code.Interval,
		Authorized: code.Authorized,
		Email:      code.Email,
	}, nil
}

// GetDeviceCode retrieves a device code by its code.
func (s *LocalStorage) GetDeviceCode(ctx context.Context, code string) (*DeviceCode, error) {
	dc := s.deviceCodes.Get(code)
	if dc == nil {
		return nil, nil
	}
	return &DeviceCode{
		Code:       dc.Code,
		UserCode:   dc.UserCode,
		ExpiresAt:  dc.ExpiresAt,
		Interval:   dc.Interval,
		Authorized: dc.Authorized,
		Email:      dc.Email,
	}, nil
}

// GetDeviceCodeByUserCode retrieves a device code by its user code.
func (s *LocalStorage) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	dc := s.deviceCodes.GetByUserCode(userCode)
	if dc == nil {
		return nil, nil
	}
	return &DeviceCode{
		Code:       dc.Code,
		UserCode:   dc.UserCode,
		ExpiresAt:  dc.ExpiresAt,
		Interval:   dc.Interval,
		Authorized: dc.Authorized,
		Email:      dc.Email,
	}, nil
}

// AuthorizeDeviceCode marks a device code as authorized.
func (s *LocalStorage) AuthorizeDeviceCode(ctx context.Context, code, email string) (bool, error) {
	return s.deviceCodes.Authorize(code, email), nil
}

// GetAccount retrieves an account by ID.
func (s *LocalStorage) GetAccount(ctx context.Context, accountID string) (*Account, error) {
	acc, err := s.accounts.GetByID(accountID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return storeAccountToStorage(acc), nil
}

// GetAccountByEmail retrieves an account by any email in its bucket.
func (s *LocalStorage) GetAccountByEmail(ctx context.Context, email string) (*Account, error) {
	acc, err := s.accounts.GetByEmail(email)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return storeAccountToStorage(acc), nil
}

// FindOrCreateByEmails finds or creates an account, handling merges.
func (s *LocalStorage) FindOrCreateByEmails(ctx context.Context, emails []string, verifiedVia string) (*Account, error) {
	acc, err := s.accounts.FindOrCreateByEmails(emails, verifiedVia)
	if err != nil {
		return nil, err
	}
	return storeAccountToStorage(acc), nil
}

// GetEmailBucket returns all emails associated with an account.
func (s *LocalStorage) GetEmailBucket(ctx context.Context, email string) ([]string, error) {
	return s.accounts.GetEmailBucket(email)
}

// UpdatePlan updates an account's plan.
func (s *LocalStorage) UpdatePlan(ctx context.Context, accountID, plan string) error {
	return s.accounts.UpdatePlan(accountID, plan)
}

// RecordUsage records bandwidth usage for an account.
func (s *LocalStorage) RecordUsage(ctx context.Context, accountID string, bytes int64) error {
	return s.accounts.RecordUsage(accountID, bytes)
}

// GetMonthlyUsage returns the current month's usage for an account.
func (s *LocalStorage) GetMonthlyUsage(ctx context.Context, accountID string) (int64, error) {
	return s.accounts.GetMonthlyUsage(accountID)
}

// RegisterTunnel registers an active tunnel and checks limits.
func (s *LocalStorage) RegisterTunnel(ctx context.Context, tunnelID, accountID, nodeAddress string) (*TunnelRegistration, error) {
	s.activeTunnelsMu.Lock()
	defer s.activeTunnelsMu.Unlock()

	// Count current tunnels for this account
	count := int32(0)
	for _, accID := range s.activeTunnels {
		if accID == accountID {
			count++
		}
	}

	// Get account plan to determine limit
	maxAllowed := int32(FreeTunnelLimit)
	acc, err := s.accounts.GetByID(accountID)
	if err == nil && acc.Plan == "pro" {
		maxAllowed = ProTunnelLimit
	}

	// Check if limit exceeded
	if count >= maxAllowed {
		return &TunnelRegistration{
			Allowed:      false,
			Reason:       "tunnel limit reached",
			CurrentCount: count,
			MaxAllowed:   maxAllowed,
		}, nil
	}

	// Register the tunnel
	s.activeTunnels[tunnelID] = accountID

	return &TunnelRegistration{
		Allowed:      true,
		CurrentCount: count + 1,
		MaxAllowed:   maxAllowed,
	}, nil
}

// UnregisterTunnel removes an active tunnel.
func (s *LocalStorage) UnregisterTunnel(ctx context.Context, tunnelID string) error {
	s.activeTunnelsMu.Lock()
	defer s.activeTunnelsMu.Unlock()
	delete(s.activeTunnels, tunnelID)
	return nil
}

// GetTunnelCount returns the number of active tunnels for an account.
func (s *LocalStorage) GetTunnelCount(ctx context.Context, accountID string) (int32, error) {
	s.activeTunnelsMu.RLock()
	defer s.activeTunnelsMu.RUnlock()

	count := int32(0)
	for _, accID := range s.activeTunnels {
		if accID == accountID {
			count++
		}
	}
	return count, nil
}

// DeviceCodeStore returns the underlying device code store for direct access.
// Used by handlers that need the raw store interface.
func (s *LocalStorage) DeviceCodeStore() *store.DeviceCodeStore {
	return s.deviceCodes
}

// AccountStore returns the underlying account store for direct access.
// Used by handlers that need the raw store interface.
func (s *LocalStorage) AccountStore() *store.AccountStore {
	return s.accounts
}

func storeAccountToStorage(acc *store.Account) *Account {
	emails := make([]AccountEmail, len(acc.Emails))
	for i, e := range acc.Emails {
		emails[i] = AccountEmail{
			Email:       e.Email,
			VerifiedVia: e.VerifiedVia,
			AddedAt:     e.AddedAt,
		}
	}
	return &Account{
		ID:           acc.ID,
		PrimaryEmail: acc.PrimaryEmail,
		Plan:         acc.Plan,
		CreatedAt:    acc.CreatedAt,
		Emails:       emails,
	}
}
