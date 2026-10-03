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

// OAuth code RPCs use the same TLS/node-secret boundary as grant management.
func (s *LoginNodeDBServer) CreateOAuthCode(ctx context.Context, req *internalv1.CreateOAuthCodeRequest) (*internalv1.CreateOAuthCodeResponse, error) {
	err := s.storage.CreateOAuthCode(ctx, store.OAuthCodeCreate{Code: req.Code, ConsentID: req.ConsentId, AccountID: req.AccountId, EndpointID: req.EndpointId, ClientID: req.ClientId, RedirectURI: req.RedirectUri, Resource: req.Resource, Scope: req.Scope, CodeChallenge: req.CodeChallenge, ExpiresAt: time.UnixMilli(req.ExpiresAtUnixMs).UTC(), GrantExpiresAt: time.UnixMilli(req.GrantExpiresAtUnixMs).UTC(), RequestLimit: req.RequestLimit, Label: req.Label})
	if err != nil {
		return nil, oauthCodeStorageError(err)
	}
	return &internalv1.CreateOAuthCodeResponse{}, nil
}
func (s *LoginNodeDBServer) ExchangeOAuthCode(ctx context.Context, req *internalv1.ExchangeOAuthCodeRequest) (*internalv1.CreateGrantResponse, error) {
	g, token, err := s.storage.ExchangeOAuthCode(ctx, store.OAuthCodeExchange{Code: req.Code, ClientID: req.ClientId, RedirectURI: req.RedirectUri, Resource: req.Resource, CodeChallenge: req.CodeChallenge})
	if err != nil {
		return nil, oauthCodeStorageError(err)
	}
	return &internalv1.CreateGrantResponse{Grant: storage.GrantToProto(g), Token: token}, nil
}
func oauthCodeStorageError(err error) error {
	switch {
	case errors.Is(err, store.ErrOAuthInvalidRequest):
		return status.Error(codes.InvalidArgument, "invalid OAuth request")
	case errors.Is(err, store.ErrOAuthInvalidGrant):
		return status.Error(codes.FailedPrecondition, "invalid OAuth authorization code")
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "OAuth operation canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "OAuth operation deadline exceeded")
	default:
		return status.Error(codes.Internal, "OAuth code storage unavailable")
	}
}
