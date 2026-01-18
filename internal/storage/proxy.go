package storage

import (
	"context"
	"sync"
	"time"

	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// ProxyStorage implements Storage by proxying to the login node via gRPC.
// Used by non-login nodes that don't have direct database access.
type ProxyStorage struct {
	mu     sync.RWMutex
	conn   *grpc.ClientConn
	client internalv1.LoginNodeDBClient
}

// NewProxyStorage creates a new ProxyStorage.
// Call SetConnection to configure the login node connection.
func NewProxyStorage() *ProxyStorage {
	return &ProxyStorage{}
}

// SetConnection sets the gRPC connection to the login node.
func (s *ProxyStorage) SetConnection(conn *grpc.ClientConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn = conn
	if conn != nil {
		s.client = internalv1.NewLoginNodeDBClient(conn)
	} else {
		s.client = nil
	}
}

// Available returns true if connected to the login node.
func (s *ProxyStorage) Available() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.conn == nil {
		return false
	}
	state := s.conn.GetState()
	return state == connectivity.Idle || state == connectivity.Connecting || state == connectivity.Ready
}

func (s *ProxyStorage) getClient() internalv1.LoginNodeDBClient {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.client
}

// CreateDeviceCode creates a new device code for CLI login.
func (s *ProxyStorage) CreateDeviceCode(ctx context.Context) (*DeviceCode, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.CreateDeviceCode(ctx, &internalv1.CreateDeviceCodeRequest{})
	if err != nil {
		return nil, err
	}
	if !resp.Found {
		return nil, nil
	}
	return &DeviceCode{
		Code:       resp.Code,
		UserCode:   resp.UserCode,
		ExpiresAt:  time.Unix(resp.ExpiresAt, 0),
		Interval:   int(resp.Interval),
		Authorized: resp.Authorized,
		Email:      resp.Email,
	}, nil
}

// GetDeviceCode retrieves a device code by its code.
func (s *ProxyStorage) GetDeviceCode(ctx context.Context, code string) (*DeviceCode, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.GetDeviceCode(ctx, &internalv1.GetDeviceCodeRequest{Code: code})
	if err != nil {
		return nil, err
	}
	if !resp.Found {
		return nil, nil
	}
	return &DeviceCode{
		Code:       resp.Code,
		UserCode:   resp.UserCode,
		ExpiresAt:  time.Unix(resp.ExpiresAt, 0),
		Interval:   int(resp.Interval),
		Authorized: resp.Authorized,
		Email:      resp.Email,
	}, nil
}

// GetDeviceCodeByUserCode retrieves a device code by its user code.
func (s *ProxyStorage) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.GetDeviceCode(ctx, &internalv1.GetDeviceCodeRequest{UserCode: userCode})
	if err != nil {
		return nil, err
	}
	if !resp.Found {
		return nil, nil
	}
	return &DeviceCode{
		Code:       resp.Code,
		UserCode:   resp.UserCode,
		ExpiresAt:  time.Unix(resp.ExpiresAt, 0),
		Interval:   int(resp.Interval),
		Authorized: resp.Authorized,
		Email:      resp.Email,
	}, nil
}

// AuthorizeDeviceCode marks a device code as authorized.
func (s *ProxyStorage) AuthorizeDeviceCode(ctx context.Context, code, email string) (bool, error) {
	client := s.getClient()
	if client == nil {
		return false, ErrNotAvailable
	}
	resp, err := client.AuthorizeDeviceCode(ctx, &internalv1.AuthorizeDeviceCodeRequest{
		Code:  code,
		Email: email,
	})
	if err != nil {
		return false, err
	}
	return resp.Success, nil
}

// GetAccount retrieves an account by ID.
func (s *ProxyStorage) GetAccount(ctx context.Context, accountID string) (*Account, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.GetAccount(ctx, &internalv1.GetAccountRequest{AccountId: accountID})
	if err != nil {
		return nil, err
	}
	if !resp.Found {
		return nil, nil
	}
	return protoAccountToStorage(resp), nil
}

// GetAccountByEmail retrieves an account by any email in its bucket.
func (s *ProxyStorage) GetAccountByEmail(ctx context.Context, email string) (*Account, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.GetAccountByEmail(ctx, &internalv1.GetAccountByEmailRequest{Email: email})
	if err != nil {
		return nil, err
	}
	if !resp.Found {
		return nil, nil
	}
	return protoAccountToStorage(resp), nil
}

// FindOrCreateByEmails finds or creates an account, handling merges.
func (s *ProxyStorage) FindOrCreateByEmails(ctx context.Context, emails []string, verifiedVia string) (*Account, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.FindOrCreateByEmails(ctx, &internalv1.FindOrCreateByEmailsRequest{
		Emails:      emails,
		VerifiedVia: verifiedVia,
	})
	if err != nil {
		return nil, err
	}
	return protoAccountToStorage(resp), nil
}

// GetEmailBucket returns all emails associated with an account.
func (s *ProxyStorage) GetEmailBucket(ctx context.Context, email string) ([]string, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.GetEmailBucket(ctx, &internalv1.GetEmailBucketRequest{Email: email})
	if err != nil {
		return nil, err
	}
	return resp.Emails, nil
}

// UpdatePlan updates an account's plan.
func (s *ProxyStorage) UpdatePlan(ctx context.Context, accountID, plan string) error {
	client := s.getClient()
	if client == nil {
		return ErrNotAvailable
	}
	_, err := client.UpdatePlan(ctx, &internalv1.UpdatePlanRequest{
		AccountId: accountID,
		Plan:      plan,
	})
	return err
}

// RecordUsage records bandwidth usage for an account.
func (s *ProxyStorage) RecordUsage(ctx context.Context, accountID string, bytes int64) error {
	client := s.getClient()
	if client == nil {
		return ErrNotAvailable
	}
	_, err := client.RecordUsage(ctx, &internalv1.RecordUsageRequest{
		AccountId: accountID,
		Bytes:     bytes,
	})
	return err
}

// GetMonthlyUsage returns the current month's usage for an account.
func (s *ProxyStorage) GetMonthlyUsage(ctx context.Context, accountID string) (int64, error) {
	client := s.getClient()
	if client == nil {
		return 0, ErrNotAvailable
	}
	resp, err := client.GetMonthlyUsage(ctx, &internalv1.GetMonthlyUsageRequest{AccountId: accountID})
	if err != nil {
		return 0, err
	}
	return resp.BytesUsed, nil
}

// RegisterTunnel registers an active tunnel and checks limits.
func (s *ProxyStorage) RegisterTunnel(ctx context.Context, tunnelID, accountID, nodeAddress string) (*TunnelRegistration, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.RegisterTunnel(ctx, &internalv1.RegisterTunnelRequest{
		TunnelId:    tunnelID,
		AccountId:   accountID,
		NodeAddress: nodeAddress,
	})
	if err != nil {
		return nil, err
	}
	return &TunnelRegistration{
		Allowed:      resp.Allowed,
		Reason:       resp.Reason,
		CurrentCount: resp.CurrentCount,
		MaxAllowed:   resp.MaxAllowed,
	}, nil
}

// UnregisterTunnel removes an active tunnel.
func (s *ProxyStorage) UnregisterTunnel(ctx context.Context, tunnelID string) error {
	client := s.getClient()
	if client == nil {
		return ErrNotAvailable
	}
	_, err := client.UnregisterTunnel(ctx, &internalv1.UnregisterTunnelRequest{TunnelId: tunnelID})
	return err
}

// GetTunnelCount returns the number of active tunnels for an account.
func (s *ProxyStorage) GetTunnelCount(ctx context.Context, accountID string) (int32, error) {
	client := s.getClient()
	if client == nil {
		return 0, ErrNotAvailable
	}
	resp, err := client.GetTunnelCount(ctx, &internalv1.GetTunnelCountRequest{AccountId: accountID})
	if err != nil {
		return 0, err
	}
	return resp.Count, nil
}

func protoAccountToStorage(resp *internalv1.AccountResponse) *Account {
	emails := make([]AccountEmail, len(resp.Emails))
	for i, e := range resp.Emails {
		emails[i] = AccountEmail{
			Email:       e.Email,
			VerifiedVia: e.VerifiedVia,
			AddedAt:     time.Unix(e.AddedAt, 0),
		}
	}
	return &Account{
		ID:           resp.Id,
		PrimaryEmail: resp.PrimaryEmail,
		Plan:         resp.Plan,
		CreatedAt:    time.Unix(resp.CreatedAt, 0),
		Emails:       emails,
	}
}
