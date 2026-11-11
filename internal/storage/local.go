package storage

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/common"
	"strings"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
)

// LocalStorage implements Storage using local SQLite stores.
// Used by the login node for direct database access.
type LocalStorage struct {
	deviceCodes      *store.DeviceCodeStore
	accounts         *store.AccountStore
	db               *sql.DB
	stripeAutomation *store.StripeAutomation

	// Active tunnels tracked in memory
	// Maps tunnel_id -> account_id
	activeTunnels   map[string]string
	activeTunnelsMu sync.RWMutex

	// Magic link rate limiting
	// Maps email -> list of request times
	magicLinkRequests   map[string][]time.Time
	magicLinkRequestsMu sync.Mutex

	// now is the clock source for time-dependent behavior (magic-token TTL
	// cleanup and magic-link rate limiting). It defaults to time.Now and is
	// used via currentTime so tests can inject a deterministic fake clock
	// (the only seam needed to test expiry and rate-limit windows).
	now func() time.Time
}

// currentTime returns the injected clock time, falling back to the wall clock
// when no clock was injected (e.g. LocalStorage built directly in tests).
func (s *LocalStorage) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// NewLocalStorage creates a new LocalStorage backed by SQLite.
func NewLocalStorage(db *sql.DB) *LocalStorage {
	s := &LocalStorage{
		deviceCodes:       store.NewDeviceCodeStore(db),
		accounts:          store.NewAccountStore(db),
		db:                db,
		activeTunnels:     make(map[string]string),
		magicLinkRequests: make(map[string][]time.Time),
		now:               time.Now,
	}
	return s
}

func NewLocalStorageWithClock(db *sql.DB, now func() time.Time) *LocalStorage {
	s := NewLocalStorage(db)
	if now != nil {
		s.now = now
	}
	return s
}

// cleanupExpiredJTIsOnce removes expired replay records using the same clock as redemption.
func (s *LocalStorage) cleanupExpiredJTIsOnce() error {
	_, err := s.db.Exec("DELETE FROM used_magic_tokens WHERE expires_at <= ?", s.currentTime().Unix())
	return err
}

// Available returns true since local storage is always available on login node.
func (s *LocalStorage) Available() bool {
	return true
}

// CheckHealth confirms the login node can read its persistent account schema.
func (s *LocalStorage) CheckHealth(ctx context.Context) error {
	if s.db == nil {
		return ErrNotAvailable
	}
	var exists int
	return s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM accounts LIMIT 1)").Scan(&exists)
}

// CreateDeviceCode creates a new device code for CLI login.
func (s *LocalStorage) CreateDeviceCode(ctx context.Context) (*DeviceCode, error) {
	return s.CreateDeviceCodeForPurpose(ctx, "publisher", "")
}

func (s *LocalStorage) CreateDeviceCodeForPurpose(ctx context.Context, purpose, accountID string) (*DeviceCode, error) {
	code, err := s.deviceCodes.CreateForPurpose(purpose, accountID)
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
		Purpose:    code.Purpose, AccountID: code.AccountID,
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
		Purpose:    dc.Purpose, AccountID: dc.AccountID,
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
		Purpose:    dc.Purpose, AccountID: dc.AccountID,
	}, nil
}

// AuthorizeDeviceCode marks a device code as authorized.
func (s *LocalStorage) AuthorizeDeviceCode(ctx context.Context, code, email string) (bool, error) {
	return s.deviceCodes.Authorize(code, email), nil
}

// GetAccount retrieves an account by ID.
func (s *LocalStorage) GetAccount(ctx context.Context, accountID string) (*Account, error) {
	acc, err := s.accounts.GetByIDContext(ctx, accountID)
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
	acc, err := s.accounts.GetByEmailContext(ctx, email)
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
	acc, err := s.accounts.FindOrCreateByEmailsContext(ctx, emails, verifiedVia)
	if err != nil {
		return nil, err
	}
	return storeAccountToStorage(acc), nil
}

// GetEmailBucket returns all emails associated with an account.
func (s *LocalStorage) GetEmailBucket(ctx context.Context, email string) ([]string, error) {
	return s.accounts.GetEmailBucketContext(ctx, email)
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
	acc, err := s.accounts.GetByIDContext(ctx, accountID)
	if err != nil {
		return nil, err
	}

	accountID = acc.ID
	if acc.OperationalState != "active" {
		return &TunnelRegistration{Allowed: false, Reason: "account_suspended"}, nil
	}

	// Every node registers here, so reservation ownership is authoritative
	// even when the ingress node has no local account database.
	namespaceOwner, scoped, err := s.accounts.NamespaceTunnelOwner(ctx, tunnelID, s.currentTime())
	if err != nil {
		return nil, err
	}
	if scoped && namespaceOwner != accountID {
		return &TunnelRegistration{Allowed: false, Reason: "namespace app name requires its verified owning account"}, nil
	}
	owner := namespaceOwner
	if !scoped {
		owner, err = s.accounts.GetSubdomainOwner(tunnelID)
	}
	if err != nil {
		return nil, err
	}
	if owner != "" && owner != accountID {
		return &TunnelRegistration{Allowed: false, Reason: "subdomain is reserved by another user"}, nil
	}

	// Check if tunnel ID already exists (cross-node duplicate check)
	if _, exists := s.activeTunnels[tunnelID]; exists {
		return &TunnelRegistration{
			Allowed: false,
			Reason:  "tunnel ID already in use",
		}, nil
	}

	// Count current tunnels for this account
	count, err := s.canonicalTunnelCount(accountID)
	if err != nil {
		return nil, err
	}

	// Get account plan to determine limit
	maxAllowed := int32(FreeTunnelLimit)
	if acc.Plan == "pro" {
		maxAllowed = ProTunnelLimit
	}
	// A denied publisher must not consume a durable name reservation.
	if count >= maxAllowed {
		return &TunnelRegistration{
			Allowed:      false,
			Reason:       "tunnel limit reached",
			CurrentCount: count,
			MaxAllowed:   maxAllowed,
		}, nil
	}

	var notice, noticeCode string

	// Auto-claim within each plan allowance on replicas and the login node.
	// A full reservation allowance still permits an unreserved active name.
	if !scoped && owner == "" {
		_ = s.accounts.ReserveSubdomain(accountID, tunnelID)
		owner, err = s.accounts.GetSubdomainOwner(tunnelID)
		if err != nil {
			return nil, err
		}
		if owner != "" && owner != accountID {
			return &TunnelRegistration{Allowed: false, Reason: "subdomain is reserved by another user"}, nil
		}
	}

	if !scoped && owner == "" && acc.Plan == "free" {
		reservations, err := s.accounts.GetReservedSubdomains(accountID)
		if err == nil && len(reservations) >= store.FreeReservedSubdomains {
			notice = "This name won't be kept while you're offline. Free keeps 1 name; Pro keeps 10 for $5 a month or $48 a year. Upgrade: https://tunn.to/upgrade?period=monthly. Pricing: https://tunn.to/pricing"
			noticeCode = "name_not_kept"
		}
	}

	// Register the tunnel
	s.activeTunnels[tunnelID] = accountID

	return &TunnelRegistration{
		Allowed:      true,
		Notice:       notice,
		NoticeCode:   noticeCode,
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

	if account, err := s.accounts.GetByIDContext(ctx, accountID); err == nil {
		accountID = account.ID
	} else if err != sql.ErrNoRows {
		return 0, err
	}
	count, err := s.canonicalTunnelCount(accountID)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// Caller holds activeTunnelsMu. Live registrations can retain an absorbed UUID
// even when the account merge happened through a different AccountStore handle.
func (s *LocalStorage) canonicalTunnelCount(accountID string) (int32, error) {
	var count int32
	resolved := make(map[string]string)
	for _, id := range s.activeTunnels {
		canonical := id
		if id != accountID {
			var ok bool
			canonical, ok = resolved[id]
			if !ok {
				account, err := s.accounts.GetByID(id)
				if err != nil {
					return 0, err
				}
				canonical = account.ID
				resolved[id] = canonical
			}
		}
		if canonical == accountID {
			count++
		}
	}
	return count, nil
}

// MarkMagicTokenUsed marks a magic link JTI as used (replay protection).
// Returns wasUnused=true if token was unused and is now marked.
// Returns wasUnused=false if token was already used (replay attempt).
func (s *LocalStorage) MarkMagicTokenUsed(ctx context.Context, jti string, expiry time.Time) (bool, error) {
	if jti == "" || expiry.Unix() <= s.currentTime().Unix() {
		return false, nil
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM used_magic_tokens WHERE expires_at <= ?", s.currentTime().Unix()); err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO used_magic_tokens (jti, expires_at)
		SELECT ?, ? WHERE ? > ?
		ON CONFLICT(jti) DO NOTHING
	`, jti, expiry.Unix(), expiry.Unix(), s.currentTime().Unix())
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
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
	if s.db == nil {
		return false, 0, time.Time{}, ErrNotAvailable
	}
	if err := s.db.PingContext(ctx); err != nil {
		return false, 0, time.Time{}, err
	}
	s.magicLinkRequestsMu.Lock()
	defer s.magicLinkRequestsMu.Unlock()

	now := s.currentTime()
	windowStart := now.Add(-magicLinkRateWindow)
	email = common.NormalizeEmail(email)
	if len(email) > 254 || !strings.Contains(email, "@") {
		return false, 0, now, fmt.Errorf("invalid email")
	}
	if s.magicLinkRequests == nil {
		s.magicLinkRequests = make(map[string][]time.Time)
	}
	for key, requests := range s.magicLinkRequests {
		if len(requests) == 0 || !requests[len(requests)-1].After(windowStart) {
			delete(s.magicLinkRequests, key)
		}
	}
	if _, exists := s.magicLinkRequests[email]; !exists && len(s.magicLinkRequests) >= 4096 {
		return false, 0, now.Add(magicLinkRateWindow), nil
	}

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
		BillingState:        acc.BillingState,
		BillingNotice:       acc.BillingNotice,
		OperationalState:    acc.OperationalState,
		OperationalVersion:  acc.OperationalVersion,
		BrowserSessionEpoch: acc.BrowserSessionEpoch,
		ID:                  acc.ID,
		PrimaryEmail:        acc.PrimaryEmail,
		Plan:                acc.Plan,
		CreatedAt:           acc.CreatedAt,
		Emails:              emails,
	}
}

func (s *LocalStorage) LookupAccountStatus(ctx context.Context, id string) (*store.AccountStatus, error) {
	return store.NewOperationsStore(s.db, nil).LookupAccountStatus(ctx, id)
}
func (s *LocalStorage) OperationsStore() *store.OperationsStore {
	return store.NewOperationsStore(s.db, nil)
}
func (s *LocalStorage) ProcessBillingEvent(ctx context.Context, e store.BillingEvent) (*store.BillingResult, error) {
	if s.stripeAutomation != nil {
		return s.stripeAutomation.Process(ctx, s.OperationsStore(), e)
	}
	return s.OperationsStore().ProcessBillingEvent(ctx, e)
}
func (s *LocalStorage) IntakeReport(ctx context.Context, id, category, endpoint string) (*store.IncidentReport, error) {
	return s.OperationsStore().IntakeReport(ctx, id, category, endpoint)
}

func (s *LocalStorage) BeginBillingCheckout(ctx context.Context, id string) (string, error) {
	return s.OperationsStore().BeginBillingCheckout(ctx, id)
}

func (s *LocalStorage) PrepareBillingCheckout(ctx context.Context, id, destination string) (string, string, error) {
	return s.OperationsStore().PrepareBillingCheckout(ctx, id, destination)
}

func (s *LocalStorage) FindOrCreateGoogleIdentity(ctx context.Context, subject, email, hostedDomain string, verified bool) (*Account, error) {
	acc, err := s.accounts.FindOrCreateGoogleIdentity(ctx, subject, email, hostedDomain, verified)
	if err != nil {
		return nil, err
	}
	return storeAccountToStorage(acc), nil
}

func (s *LocalStorage) CheckManagementDevice(ctx context.Context, id, email, accountID string) (bool, error) {
	var owner, bound string
	err := s.db.QueryRowContext(ctx, `SELECT email,account_id FROM durable_devices WHERE id=? AND purpose='management' AND revoked=0`, id).Scan(&owner, &bound)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if common.NormalizeEmail(owner) != common.NormalizeEmail(email) || bound != accountID {
		return false, nil
	}
	original, err := s.GetAccount(ctx, bound)
	if err != nil || original == nil {
		return false, err
	}
	current, err := s.GetAccountByEmail(ctx, email)
	if err != nil || current == nil {
		return false, err
	}
	return original.ID == current.ID && current.OperationalState == "active", nil
}

func (s *LocalStorage) MutateAccountEmail(ctx context.Context, id, email, action string) (*Account, error) {
	a, err := s.accounts.MutateAccountEmail(ctx, id, email, action)
	if err != nil {
		return nil, err
	}
	return storeAccountToStorage(a), nil
}

func (s *LocalStorage) LinkAccountEmail(ctx context.Context, id, email, jti string, expiry time.Time) (*Account, error) {
	a, err := s.accounts.LinkAccountEmail(ctx, id, email, jti, expiry)
	if err != nil {
		return nil, err
	}
	return storeAccountToStorage(a), nil
}

func (s *LocalStorage) RevokeBrowserSessions(ctx context.Context, id, expected string) error {
	return s.accounts.RevokeBrowserSessions(ctx, id, expected)
}

// ConfigureStripeAutomation must run before serving webhook or node RPC intake.
func (s *LocalStorage) ConfigureStripeAutomation(key string, prices []string) {
	s.stripeAutomation = store.NewStripeAutomation(key, prices, nil)
}
