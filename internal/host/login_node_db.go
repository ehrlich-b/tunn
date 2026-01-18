package host

import (
	"context"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LoginNodeDBServer implements the LoginNodeDB gRPC service for the login node.
// This is the authoritative source for all database operations in the cluster.
// Non-login nodes connect to this service via gRPC.
type LoginNodeDBServer struct {
	internalv1.UnimplementedLoginNodeDBServer
	storage *storage.LocalStorage
}

// NewLoginNodeDBServer creates a new LoginNodeDBServer with the given local storage.
func NewLoginNodeDBServer(localStorage *storage.LocalStorage) *LoginNodeDBServer {
	return &LoginNodeDBServer{
		storage: localStorage,
	}
}

// RecordUsage records bandwidth usage for an account
func (s *LoginNodeDBServer) RecordUsage(ctx context.Context, req *internalv1.RecordUsageRequest) (*internalv1.RecordUsageResponse, error) {
	if err := s.storage.RecordUsage(ctx, req.AccountId, req.Bytes); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to record usage: %v", err)
	}
	return &internalv1.RecordUsageResponse{}, nil
}

// GetMonthlyUsage returns the current month's usage for an account
func (s *LoginNodeDBServer) GetMonthlyUsage(ctx context.Context, req *internalv1.GetMonthlyUsageRequest) (*internalv1.GetMonthlyUsageResponse, error) {
	bytes, err := s.storage.GetMonthlyUsage(ctx, req.AccountId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get usage: %v", err)
	}
	return &internalv1.GetMonthlyUsageResponse{BytesUsed: bytes}, nil
}

// CreateDeviceCode creates a new device code for CLI login
func (s *LoginNodeDBServer) CreateDeviceCode(ctx context.Context, req *internalv1.CreateDeviceCodeRequest) (*internalv1.DeviceCodeResponse, error) {
	code, err := s.storage.CreateDeviceCode(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create device code: %v", err)
	}
	return &internalv1.DeviceCodeResponse{
		Code:       code.Code,
		UserCode:   code.UserCode,
		ExpiresAt:  code.ExpiresAt.Unix(),
		Interval:   int32(code.Interval),
		Authorized: false,
		Found:      true,
	}, nil
}

// GetDeviceCode retrieves a device code by code or user_code
func (s *LoginNodeDBServer) GetDeviceCode(ctx context.Context, req *internalv1.GetDeviceCodeRequest) (*internalv1.DeviceCodeResponse, error) {
	var code *storage.DeviceCode
	var err error

	if req.UserCode != "" {
		code, err = s.storage.GetDeviceCodeByUserCode(ctx, req.UserCode)
	} else {
		code, err = s.storage.GetDeviceCode(ctx, req.Code)
	}

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get device code: %v", err)
	}
	if code == nil {
		return &internalv1.DeviceCodeResponse{Found: false}, nil
	}

	return &internalv1.DeviceCodeResponse{
		Code:       code.Code,
		UserCode:   code.UserCode,
		ExpiresAt:  code.ExpiresAt.Unix(),
		Interval:   int32(code.Interval),
		Authorized: code.Authorized,
		Email:      code.Email,
		Found:      true,
	}, nil
}

// AuthorizeDeviceCode marks a device code as authorized with an email
func (s *LoginNodeDBServer) AuthorizeDeviceCode(ctx context.Context, req *internalv1.AuthorizeDeviceCodeRequest) (*internalv1.AuthorizeDeviceCodeResponse, error) {
	success, err := s.storage.AuthorizeDeviceCode(ctx, req.Code, req.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to authorize device code: %v", err)
	}
	return &internalv1.AuthorizeDeviceCodeResponse{Success: success}, nil
}

// GetAccount retrieves an account by ID
func (s *LoginNodeDBServer) GetAccount(ctx context.Context, req *internalv1.GetAccountRequest) (*internalv1.AccountResponse, error) {
	account, err := s.storage.GetAccount(ctx, req.AccountId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get account: %v", err)
	}
	if account == nil {
		return &internalv1.AccountResponse{Found: false}, nil
	}
	return accountToProto(account), nil
}

// GetAccountByEmail retrieves an account by any email in its bucket
func (s *LoginNodeDBServer) GetAccountByEmail(ctx context.Context, req *internalv1.GetAccountByEmailRequest) (*internalv1.AccountResponse, error) {
	account, err := s.storage.GetAccountByEmail(ctx, req.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get account: %v", err)
	}
	if account == nil {
		return &internalv1.AccountResponse{Found: false}, nil
	}
	return accountToProto(account), nil
}

// FindOrCreateByEmails finds or creates an account, handling merges
func (s *LoginNodeDBServer) FindOrCreateByEmails(ctx context.Context, req *internalv1.FindOrCreateByEmailsRequest) (*internalv1.AccountResponse, error) {
	account, err := s.storage.FindOrCreateByEmails(ctx, req.Emails, req.VerifiedVia)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to find or create account: %v", err)
	}
	return accountToProto(account), nil
}

// GetEmailBucket returns all emails associated with an account containing the given email
func (s *LoginNodeDBServer) GetEmailBucket(ctx context.Context, req *internalv1.GetEmailBucketRequest) (*internalv1.GetEmailBucketResponse, error) {
	emails, err := s.storage.GetEmailBucket(ctx, req.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get email bucket: %v", err)
	}
	return &internalv1.GetEmailBucketResponse{Emails: emails}, nil
}

// UpdatePlan updates an account's plan
func (s *LoginNodeDBServer) UpdatePlan(ctx context.Context, req *internalv1.UpdatePlanRequest) (*internalv1.UpdatePlanResponse, error) {
	if err := s.storage.UpdatePlan(ctx, req.AccountId, req.Plan); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update plan: %v", err)
	}
	return &internalv1.UpdatePlanResponse{}, nil
}

// RegisterTunnel registers an active tunnel and checks limits
func (s *LoginNodeDBServer) RegisterTunnel(ctx context.Context, req *internalv1.RegisterTunnelRequest) (*internalv1.RegisterTunnelResponse, error) {
	reg, err := s.storage.RegisterTunnel(ctx, req.TunnelId, req.AccountId, req.NodeAddress)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to register tunnel: %v", err)
	}
	return &internalv1.RegisterTunnelResponse{
		Allowed:      reg.Allowed,
		Reason:       reg.Reason,
		CurrentCount: reg.CurrentCount,
		MaxAllowed:   reg.MaxAllowed,
	}, nil
}

// UnregisterTunnel removes an active tunnel
func (s *LoginNodeDBServer) UnregisterTunnel(ctx context.Context, req *internalv1.UnregisterTunnelRequest) (*internalv1.UnregisterTunnelResponse, error) {
	if err := s.storage.UnregisterTunnel(ctx, req.TunnelId); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unregister tunnel: %v", err)
	}
	return &internalv1.UnregisterTunnelResponse{}, nil
}

// GetTunnelCount returns the number of active tunnels for an account
func (s *LoginNodeDBServer) GetTunnelCount(ctx context.Context, req *internalv1.GetTunnelCountRequest) (*internalv1.GetTunnelCountResponse, error) {
	count, err := s.storage.GetTunnelCount(ctx, req.AccountId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get tunnel count: %v", err)
	}
	return &internalv1.GetTunnelCountResponse{Count: count}, nil
}

// MarkMagicTokenUsed marks a magic link JTI as used (replay protection).
// Returns was_unused=true if the token was unused and is now marked.
// Returns was_unused=false if the token was already used (replay attempt).
func (s *LoginNodeDBServer) MarkMagicTokenUsed(ctx context.Context, req *internalv1.MarkMagicTokenUsedRequest) (*internalv1.MarkMagicTokenUsedResponse, error) {
	expiry := time.Unix(req.ExpiryUnix, 0)
	wasUnused, err := s.storage.MarkMagicTokenUsed(ctx, req.Jti, expiry)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to mark token used: %v", err)
	}
	return &internalv1.MarkMagicTokenUsedResponse{WasUnused: wasUnused}, nil
}

// CheckMagicLinkRateLimit checks if an email can request a magic link.
func (s *LoginNodeDBServer) CheckMagicLinkRateLimit(ctx context.Context, req *internalv1.CheckMagicLinkRateLimitRequest) (*internalv1.CheckMagicLinkRateLimitResponse, error) {
	allowed, remaining, resetAt, err := s.storage.CheckMagicLinkRateLimit(ctx, req.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check rate limit: %v", err)
	}
	return &internalv1.CheckMagicLinkRateLimitResponse{
		Allowed:     allowed,
		Remaining:   remaining,
		ResetAtUnix: resetAt.Unix(),
	}, nil
}

// accountToProto converts a storage.Account to proto AccountResponse
func accountToProto(acc *storage.Account) *internalv1.AccountResponse {
	emails := make([]*internalv1.AccountEmail, len(acc.Emails))
	for i, e := range acc.Emails {
		emails[i] = &internalv1.AccountEmail{
			Email:       e.Email,
			VerifiedVia: e.VerifiedVia,
			AddedAt:     e.AddedAt.Unix(),
		}
	}
	return &internalv1.AccountResponse{
		Found:        true,
		Id:           acc.ID,
		PrimaryEmail: acc.PrimaryEmail,
		Plan:         acc.Plan,
		CreatedAt:    acc.CreatedAt.Unix(),
		Emails:       emails,
	}
}
