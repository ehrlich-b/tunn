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

// GrantStorage is the authoritative temporary credential/admission contract.
// It is separate from Storage so legacy storage implementations cannot silently
// imply support. Unavailable implementations must fail closed at the ingress.
type GrantStorage interface {
	CreateGrant(context.Context, store.GrantCreate) (*store.Grant, string, error)
	ListGrants(context.Context, string, string) ([]store.Grant, error)
	RevokeGrant(context.Context, string, string) (bool, error)
	AdmitGrant(context.Context, store.GrantAdmissionRequest) (*store.GrantAdmission, error)
}

func (s *LocalStorage) CreateGrant(ctx context.Context, q store.GrantCreate) (*store.Grant, string, error) {
	if err := q.Validate(time.Now().UTC()); err != nil {
		return nil, "", err
	}
	// The login node tracks registrations across all publishing nodes. Hold the
	// read lock until creation completes so a disappearing or replaced endpoint
	// cannot acquire another owner's grant during this operation.
	s.activeTunnelsMu.RLock()
	defer s.activeTunnelsMu.RUnlock()
	owner, ok := s.activeTunnels[q.EndpointID]
	if !ok {
		return nil, "", store.ErrGrantNotOwned
	}
	canonicalOwner, err := s.grants.CanonicalAccountID(ctx, owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", store.ErrGrantNotOwned
	}
	if err != nil {
		return nil, "", err
	}
	canonicalCaller, err := s.grants.CanonicalAccountID(ctx, q.AccountID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", store.ErrGrantNotOwned
	}
	if err != nil {
		return nil, "", err
	}
	if canonicalOwner != canonicalCaller {
		return nil, "", store.ErrGrantNotOwned
	}
	if protocol := s.activeProtocols[q.EndpointID]; protocol != "http" && protocol != "mcp" {
		return nil, "", store.ErrGrantScopeUnsupported
	}
	return s.grants.Create(ctx, q)
}

func (s *LocalStorage) ListGrants(ctx context.Context, accountID, endpointID string) ([]store.Grant, error) {
	return s.grants.List(ctx, accountID, endpointID)
}
func (s *LocalStorage) RevokeGrant(ctx context.Context, accountID, grantID string) (bool, error) {
	return s.grants.Revoke(ctx, accountID, grantID)
}
func (s *LocalStorage) AdmitGrant(ctx context.Context, q store.GrantAdmissionRequest) (*store.GrantAdmission, error) {
	return s.grants.Admit(ctx, q)
}

func (s *ProxyStorage) CreateGrant(ctx context.Context, q store.GrantCreate) (*store.Grant, string, error) {
	client := s.getClient()
	if client == nil {
		return nil, "", ErrNotAvailable
	}
	resp, err := client.CreateGrant(ctx, &internalv1.CreateGrantRequest{AccountId: q.AccountID, EndpointId: q.EndpointID, Label: q.Label, ExpiresAtUnixMs: q.ExpiresAt.UnixMilli(), RequestLimit: q.RequestLimit})
	if err != nil {
		return nil, "", grantRPCError(err)
	}
	return GrantFromProto(resp.Grant), resp.Token, nil
}
func (s *ProxyStorage) ListGrants(ctx context.Context, accountID, endpointID string) ([]store.Grant, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.ListGrants(ctx, &internalv1.ListGrantsRequest{AccountId: accountID, EndpointId: endpointID})
	if err != nil {
		return nil, grantRPCError(err)
	}
	out := make([]store.Grant, 0, len(resp.Grants))
	for _, g := range resp.Grants {
		if g != nil {
			out = append(out, *GrantFromProto(g))
		}
	}
	return out, nil
}
func (s *ProxyStorage) RevokeGrant(ctx context.Context, accountID, grantID string) (bool, error) {
	client := s.getClient()
	if client == nil {
		return false, ErrNotAvailable
	}
	resp, err := client.RevokeGrant(ctx, &internalv1.RevokeGrantRequest{AccountId: accountID, GrantId: grantID})
	if err != nil {
		return false, grantRPCError(err)
	}
	return resp.Found, nil
}
func (s *ProxyStorage) AdmitGrant(ctx context.Context, q store.GrantAdmissionRequest) (*store.GrantAdmission, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.AdmitGrant(ctx, &internalv1.AdmitGrantRequest{AccountId: q.AccountID, EndpointId: q.EndpointID, Token: q.Token, RequestId: q.RequestID})
	if err != nil {
		return nil, grantRPCError(err)
	}
	return &store.GrantAdmission{Allowed: resp.Allowed, GrantID: resp.GrantId, Reason: resp.Reason, Status: int(resp.Status)}, nil
}

func grantRPCError(err error) error {
	switch status.Code(err) {
	case codes.InvalidArgument:
		return store.ErrInvalidGrant
	case codes.PermissionDenied:
		return store.ErrGrantNotOwned
	case codes.FailedPrecondition:
		return store.ErrGrantScopeUnsupported
	default:
		return err
	}
}

func GrantToProto(g *store.Grant) *internalv1.Grant {
	if g == nil {
		return nil
	}
	return &internalv1.Grant{Id: g.ID, AccountId: g.AccountID, EndpointId: g.EndpointID, Label: g.Label, CreatedAtUnixMs: g.CreatedAt.UnixMilli(), ExpiresAtUnixMs: g.ExpiresAt.UnixMilli(), RequestLimit: g.RequestLimit, Used: g.Used, Revoked: g.Revoked}
}
func GrantFromProto(g *internalv1.Grant) *store.Grant {
	if g == nil {
		return nil
	}
	return &store.Grant{ID: g.Id, AccountID: g.AccountId, EndpointID: g.EndpointId, Label: g.Label, CreatedAt: time.UnixMilli(g.CreatedAtUnixMs).UTC(), ExpiresAt: time.UnixMilli(g.ExpiresAtUnixMs).UTC(), RequestLimit: g.RequestLimit, Used: g.Used, Revoked: g.Revoked}
}

var _ GrantStorage = (*LocalStorage)(nil)
var _ GrantStorage = (*ProxyStorage)(nil)
var _ EndpointRegistry = (*LocalStorage)(nil)
var _ EndpointRegistry = (*ProxyStorage)(nil)
