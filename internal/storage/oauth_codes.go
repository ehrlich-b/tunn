package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type OAuthCodeStorage interface {
	CreateOAuthCode(context.Context, store.OAuthCodeCreate) error
	ExchangeOAuthCode(context.Context, store.OAuthCodeExchange) (*store.Grant, string, error)
}

// oauthEndpointOwned must be called while activeTunnelsMu is held. Ownership
// and protocol are checked at consent and again at code exchange, so a stale
// browser flow cannot authorize a replacement publisher or a TCP endpoint.
func (s *LocalStorage) oauthEndpointOwned(ctx context.Context, accountID, endpointID string) error {
	owner, ok := s.activeTunnels[endpointID]
	if !ok {
		return store.ErrOAuthInvalidGrant
	}
	canonicalOwner, err := s.grants.CanonicalAccountID(ctx, owner)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrOAuthInvalidGrant
	}
	if err != nil {
		return err
	}
	canonicalCaller, err := s.grants.CanonicalAccountID(ctx, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrOAuthInvalidGrant
	}
	if err != nil {
		return err
	}
	if canonicalOwner != canonicalCaller {
		return store.ErrOAuthInvalidGrant
	}
	if protocol := s.activeProtocols[endpointID]; protocol != "http" && protocol != "mcp" {
		return store.ErrOAuthInvalidGrant
	}
	return nil
}

func (s *LocalStorage) CreateOAuthCode(ctx context.Context, q store.OAuthCodeCreate) error {
	if err := q.Validate(time.Now().UTC()); err != nil {
		return err
	}
	s.activeTunnelsMu.RLock()
	defer s.activeTunnelsMu.RUnlock()
	if err := s.oauthEndpointOwned(ctx, q.AccountID, q.EndpointID); err != nil {
		return err
	}
	return s.oauthCodes.Create(ctx, q)
}

func (s *LocalStorage) ExchangeOAuthCode(ctx context.Context, q store.OAuthCodeExchange) (*store.Grant, string, error) {
	if err := q.Validate(); err != nil {
		return nil, "", err
	}
	s.activeTunnelsMu.RLock()
	defer s.activeTunnelsMu.RUnlock()
	accountID, endpointID, err := s.oauthCodes.Owner(ctx, q.Code)
	if err != nil {
		return nil, "", err
	}
	if err := s.oauthEndpointOwned(ctx, accountID, endpointID); err != nil {
		return nil, "", err
	}
	return s.oauthCodes.Exchange(ctx, q)
}

func (s *ProxyStorage) CreateOAuthCode(ctx context.Context, q store.OAuthCodeCreate) error {
	client := s.getClient()
	if client == nil {
		return ErrNotAvailable
	}
	_, err := client.CreateOAuthCode(ctx, &internalv1.CreateOAuthCodeRequest{Code: q.Code, ConsentId: q.ConsentID, AccountId: q.AccountID, EndpointId: q.EndpointID, ClientId: q.ClientID, RedirectUri: q.RedirectURI, Resource: q.Resource, Scope: q.Scope, CodeChallenge: q.CodeChallenge, ExpiresAtUnixMs: q.ExpiresAt.UnixMilli(), GrantExpiresAtUnixMs: q.GrantExpiresAt.UnixMilli(), RequestLimit: q.RequestLimit, Label: q.Label})
	if err != nil {
		return oauthCodeRPCError(err)
	}
	return nil
}
func (s *ProxyStorage) ExchangeOAuthCode(ctx context.Context, q store.OAuthCodeExchange) (*store.Grant, string, error) {
	client := s.getClient()
	if client == nil {
		return nil, "", ErrNotAvailable
	}
	resp, err := client.ExchangeOAuthCode(ctx, &internalv1.ExchangeOAuthCodeRequest{Code: q.Code, ClientId: q.ClientID, RedirectUri: q.RedirectURI, Resource: q.Resource, CodeChallenge: q.CodeChallenge})
	if err != nil {
		return nil, "", oauthCodeRPCError(err)
	}
	if resp.Grant == nil || resp.Token == "" {
		return nil, "", ErrNotAvailable
	}
	return GrantFromProto(resp.Grant), resp.Token, nil
}
func oauthCodeRPCError(err error) error {
	switch status.Code(err) {
	case codes.InvalidArgument:
		return store.ErrOAuthInvalidRequest
	case codes.FailedPrecondition:
		return store.ErrOAuthInvalidGrant
	default:
		return err
	}
}

var _ OAuthCodeStorage = (*LocalStorage)(nil)
var _ OAuthCodeStorage = (*ProxyStorage)(nil)
