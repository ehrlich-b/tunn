package host

import (
	"context"
	"errors"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These methods share LoginNodeDB's existing node-secret interceptor. The
// public management handler authenticates the owner; the login node also
// verifies active endpoint ownership for creation.
func (s *LoginNodeDBServer) CreateGrant(ctx context.Context, req *internalv1.CreateGrantRequest) (*internalv1.CreateGrantResponse, error) {
	g, token, err := s.storage.CreateGrant(ctx, store.GrantCreate{AccountID: req.AccountId, EndpointID: req.EndpointId, Label: req.Label, ExpiresAt: time.UnixMilli(req.ExpiresAtUnixMs).UTC(), RequestLimit: req.RequestLimit})
	if err != nil {
		return nil, grantStorageError(err)
	}
	return &internalv1.CreateGrantResponse{Grant: storage.GrantToProto(g), Token: token}, nil
}
func (s *LoginNodeDBServer) ListGrants(ctx context.Context, req *internalv1.ListGrantsRequest) (*internalv1.ListGrantsResponse, error) {
	grants, err := s.storage.ListGrants(ctx, req.AccountId, req.EndpointId)
	if err != nil {
		return nil, grantStorageError(err)
	}
	resp := &internalv1.ListGrantsResponse{}
	for i := range grants {
		resp.Grants = append(resp.Grants, storage.GrantToProto(&grants[i]))
	}
	return resp, nil
}
func (s *LoginNodeDBServer) RevokeGrant(ctx context.Context, req *internalv1.RevokeGrantRequest) (*internalv1.RevokeGrantResponse, error) {
	found, err := s.storage.RevokeGrant(ctx, req.AccountId, req.GrantId)
	if err != nil {
		return nil, grantStorageError(err)
	}
	return &internalv1.RevokeGrantResponse{Found: found}, nil
}
func (s *LoginNodeDBServer) AdmitGrant(ctx context.Context, req *internalv1.AdmitGrantRequest) (*internalv1.AdmitGrantResponse, error) {
	out, err := s.storage.AdmitGrant(ctx, store.GrantAdmissionRequest{AccountID: req.AccountId, EndpointID: req.EndpointId, Token: req.Token, RequestID: req.RequestId})
	if err != nil {
		return nil, grantStorageError(err)
	}
	return &internalv1.AdmitGrantResponse{Allowed: out.Allowed, GrantId: out.GrantID, Reason: out.Reason, Status: int32(out.Status)}, nil
}
func grantStorageError(err error) error {
	switch {
	case errors.Is(err, store.ErrInvalidGrant):
		return status.Error(codes.InvalidArgument, "invalid grant parameters")
	case errors.Is(err, store.ErrGrantNotOwned):
		return status.Error(codes.PermissionDenied, "endpoint not active or not owned by account")
	case errors.Is(err, store.ErrGrantScopeUnsupported):
		return status.Error(codes.FailedPrecondition, "grants require a registered HTTP MCP endpoint")
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "grant operation canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "grant operation deadline exceeded")
	default:
		return status.Error(codes.Internal, "grant storage unavailable")
	}
}
