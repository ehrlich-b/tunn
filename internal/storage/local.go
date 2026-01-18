package storage

import (
	"context"
	"database/sql"
	"sync"
	"time"

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

	// Magic link JTI tracking (replay protection)
	// Maps jti -> expiry time
	usedJTIs   map[string]time.Time
	usedJTIsMu sync.RWMutex

	// Magic link rate limiting
	// Maps email -> list of request times
	magicLinkRequests   map[string][]time.Time
	magicLinkRequestsMu sync.Mutex
}

// NewLocalStorage creates a new LocalStorage backed by SQLite.
func NewLocalStorage(db *sql.DB) *LocalStorage {
	s := &LocalStorage{
		deviceCodes:       store.NewDeviceCodeStore(db),
		accounts:          store.NewAccountStore(db),
		activeTunnels:     make(map[string]string),
		usedJTIs:          make(map[string]time.Time),
		magicLinkRequests: make(map[string][]time.Time),
	}
	// Start cleanup goroutine for expired JTIs
	go s.cleanupExpiredJTIs()
	return s
}

// cleanupExpiredJTIs periodically removes expired JTIs from memory
func (s *LocalStorage) cleanupExpiredJTIs() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.usedJTIsMu.Lock()
		for jti, expiry := range s.usedJTIs {
			if now.After(expiry) {
				delete(s.usedJTIs, jti)
			}
		}
		s.usedJTIsMu.Unlock()
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

	// Check if tunnel ID already exists (cross-node duplicate check)
	if _, exists := s.activeTunnels[tunnelID]; exists {
		return &TunnelRegistration{
			Allowed: false,
			Reason:  "tunnel ID already in use",
		}, nil
	}

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

// MarkMagicTokenUsed marks a magic link JTI as used (replay protection).
// Returns wasUnused=true if token was unused and is now marked.
// Returns wasUnused=false if token was already used (replay attempt).
func (s *LocalStorage) MarkMagicTokenUsed(ctx context.Context, jti string, expiry time.Time) (bool, error) {
	s.usedJTIsMu.Lock()
	defer s.usedJTIsMu.Unlock()

	if _, exists := s.usedJTIs[jti]; exists {
		return false, nil
	}

	s.usedJTIs[jti] = expiry
	return true, nil
}

// Magic link rate limiting constants
const (
	magicLinkRateWindow   = 5 * time.Minute
	magicLinkRateMaxCount = 3
)

// CheckMagicLinkRateLimit checks if an email can request a magic link.
// Returns allowed=true if the request is within rate limits.
// Also records the request if allowed.
func (s *LocalStorage) CheckMagicLinkRateLimit(ctx context.Context, email string) (bool, int32, time.Time, error) {
	s.magicLinkRequestsMu.Lock()
	defer s.magicLinkRequestsMu.Unlock()

	now := time.Now()
	windowStart := now.Add(-magicLinkRateWindow)

	// Get existing requests and filter to current window
	requests := s.magicLinkRequests[email]
	var validRequests []time.Time
	for _, t := range requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	// Calculate reset time (oldest request in window + window duration)
	var resetAt time.Time
	if len(validRequests) > 0 {
		resetAt = validRequests[0].Add(magicLinkRateWindow)
	} else {
		resetAt = now.Add(magicLinkRateWindow)
	}

	// Check if rate limited
	if len(validRequests) >= magicLinkRateMaxCount {
		remaining := int32(0)
		return false, remaining, resetAt, nil
	}

	// Record this request
	validRequests = append(validRequests, now)
	s.magicLinkRequests[email] = validRequests

	remaining := int32(magicLinkRateMaxCount - len(validRequests))
	return true, remaining, resetAt, nil
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
