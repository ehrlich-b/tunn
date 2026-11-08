// Package storage provides a unified storage interface that works across
// login nodes (local SQLite) and non-login nodes (proxy to login node).
package storage

import (
	"context"
	"errors"
	"github.com/ehrlich-b/tunn/internal/store"
	"time"
)

// AccountStatusLookup is the suspension hook shared with domain/active-stream
// enforcement. Lookup errors must fail closed; callers resolve merged UUIDs.
type AccountStatusLookup interface {
	LookupAccountStatus(context.Context, string) (*store.AccountStatus, error)
}

// ErrNotAvailable is returned when storage is not available (login node down).
var ErrNotAvailable = errors.New("storage not available")

// Tunnel limits by plan
const (
	FreeTunnelLimit = 5
	ProTunnelLimit  = 25
)

// Storage is the unified interface for all database operations.
// Login nodes use LocalStorage (SQLite), non-login nodes use ProxyStorage (gRPC).
type Storage interface {
	// Device codes for CLI login
	CreateDeviceCode(ctx context.Context) (*DeviceCode, error)
	GetDeviceCode(ctx context.Context, code string) (*DeviceCode, error)
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	AuthorizeDeviceCode(ctx context.Context, code, email string) (bool, error)

	// Account management
	GetAccount(ctx context.Context, accountID string) (*Account, error)
	GetAccountByEmail(ctx context.Context, email string) (*Account, error)
	FindOrCreateByEmails(ctx context.Context, emails []string, verifiedVia string) (*Account, error)
	GetEmailBucket(ctx context.Context, email string) ([]string, error)
	UpdatePlan(ctx context.Context, accountID, plan string) error

	// Usage tracking
	RecordUsage(ctx context.Context, accountID string, bytes int64) error
	GetMonthlyUsage(ctx context.Context, accountID string) (int64, error)

	// Active tunnel tracking (cross-node)
	RegisterTunnel(ctx context.Context, tunnelID, accountID, nodeAddress string) (*TunnelRegistration, error)
	UnregisterTunnel(ctx context.Context, tunnelID string) error
	GetTunnelCount(ctx context.Context, accountID string) (int32, error)

	// Magic link replay protection (cross-node)
	MarkMagicTokenUsed(ctx context.Context, jti string, expiry time.Time) (wasUnused bool, err error)

	// Magic link rate limiting (per-email throttle)
	CheckMagicLinkRateLimit(ctx context.Context, email string) (allowed bool, remaining int32, resetAt time.Time, err error)

	// Availability
	Available() bool
}

// DeviceCode represents a pending device authorization
type DeviceCode struct {
	Code       string
	UserCode   string
	ExpiresAt  time.Time
	Interval   int
	Authorized bool
	Email      string
	Purpose    string
	AccountID  string
}

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

// TunnelRegistration is the result of registering a tunnel
type TunnelRegistration struct {
	Notice       string
	NoticeCode   string
	Allowed      bool
	Reason       string
	CurrentCount int32
	MaxAllowed   int32
}

// BillingCheckout is implemented by the authoritative store and its node proxy.
type BillingCheckout interface {
	BeginBillingCheckout(context.Context, string) (string, error)
}

// DurableBillingCheckout resumes the intent's original payment destination.
type DurableBillingCheckout interface {
	PrepareBillingCheckout(context.Context, string, string) (string, string, error)
}

// GoogleIdentityStorage binds only authoritative Google emails to a provider subject.
type GoogleIdentityStorage interface {
	FindOrCreateGoogleIdentity(context.Context, string, string, string, bool) (*Account, error)
}

// ScopedDeviceStorage preserves consent across the login-node boundary.
type ScopedDeviceStorage interface {
	CreateDeviceCodeForPurpose(context.Context, string, string) (*DeviceCode, error)
	CheckManagementDevice(context.Context, string, string, string) (bool, error)
}

// BrowserSessionStorage revokes browser sessions without touching device credentials.
type BrowserSessionStorage interface {
	RevokeBrowserSessions(context.Context, string, string) error
}

// AccountEmailStorage is implemented locally and through the login node.
type AccountEmailStorage interface {
	LinkAccountEmail(context.Context, string, string, string, time.Time) (*Account, error)
	MutateAccountEmail(context.Context, string, string, string) (*Account, error)
}
