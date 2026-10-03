package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGrantInternalRPCOwnershipAdmissionAndRevocation(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	local := storage.NewLocalStorage(db)
	remote := ingressProxyStorage(t, local)
	ctx := context.Background()
	owner, err := remote.FindOrCreateByEmails(ctx, []string{"grant-rpc-owner@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	other, err := remote.FindOrCreateByEmails(ctx, []string{"grant-rpc-other@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	q := store.GrantCreate{AccountID: owner.ID, EndpointID: "build", Label: "Go client", ExpiresAt: time.Now().Add(time.Hour), RequestLimit: 2}
	if _, _, err := remote.CreateGrant(ctx, q); !errors.Is(err, store.ErrGrantNotOwned) {
		t.Fatalf("inactive endpoint grant=%v", err)
	}
	reg, err := remote.RegisterEndpoint(ctx, "build", owner.ID, "synthetic-node", "http")
	if err != nil || !reg.Allowed {
		t.Fatalf("registration=%+v %v", reg, err)
	}
	q.AccountID = other.ID
	if _, _, err := remote.CreateGrant(ctx, q); !errors.Is(err, store.ErrGrantNotOwned) {
		t.Fatalf("wrong owner grant=%v", err)
	}
	q.AccountID = owner.ID
	g, token, err := remote.CreateGrant(ctx, q)
	if err != nil || g == nil || token == "" {
		t.Fatalf("create=%+v err=%v", g, err)
	}
	req := store.GrantAdmissionRequest{AccountID: owner.ID, EndpointID: "build", Token: token, RequestID: "rpc-request"}
	for i := 0; i < 2; i++ {
		out, err := remote.AdmitGrant(ctx, req)
		if err != nil || !out.Allowed || out.GrantID != g.ID {
			t.Fatalf("admission=%+v %v", out, err)
		}
	}
	grants, err := remote.ListGrants(ctx, owner.ID, "build")
	if err != nil || len(grants) != 1 || grants[0].Used != 1 || grants[0].Label != "Go client" {
		t.Fatalf("RPC metadata=%+v %v", grants, err)
	}
	if found, err := remote.RevokeGrant(ctx, other.ID, g.ID); err != nil || found {
		t.Fatal("other account revoked grant")
	}
	if found, err := remote.RevokeGrant(ctx, owner.ID, g.ID); err != nil || !found {
		t.Fatalf("revoke=%v %v", found, err)
	}
	out, err := remote.AdmitGrant(ctx, req)
	if err != nil || out.Allowed || out.Status != 403 || out.Reason != "grant_revoked" {
		t.Fatalf("revoked RPC admission=%+v %v", out, err)
	}
	// Once an endpoint name is re-registered by another owner, the old grant
	// cannot grant access to that owner's private capability.
	if err := remote.UnregisterTunnel(ctx, "build"); err != nil {
		t.Fatal(err)
	}
	if reg, err := remote.RegisterEndpoint(ctx, "build", other.ID, "node-two", "http"); err != nil || !reg.Allowed {
		t.Fatal("replacement registration failed")
	}
	req.AccountID = other.ID
	out, err = remote.AdmitGrant(ctx, req)
	if err != nil || out.Allowed || out.Reason != "grant_invalid" {
		t.Fatalf("replacement granted=%+v %v", out, err)
	}
	remote.SetConnection(nil)
	if out, err := remote.AdmitGrant(ctx, req); !errors.Is(err, storage.ErrNotAvailable) || out != nil {
		t.Fatal("unavailable RPC admitted")
	}
}

func TestGrantCreationAfterAccountMerge(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	local := storage.NewLocalStorage(db)
	ctx := context.Background()
	old, err := local.FindOrCreateByEmails(ctx, []string{"cached-owner@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	next, err := local.FindOrCreateByEmails(ctx, []string{"merged-owner@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := local.UpdatePlan(ctx, next.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if reg, err := local.RegisterEndpoint(ctx, "build", old.ID, "node", "http"); err != nil || !reg.Allowed {
		t.Fatal("register failed")
	}
	merged, err := local.FindOrCreateByEmails(ctx, []string{old.PrimaryEmail, next.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	g, _, err := local.CreateGrant(ctx, store.GrantCreate{AccountID: merged.ID, EndpointID: "build", ExpiresAt: time.Now().Add(time.Hour), RequestLimit: 2})
	if err != nil || g.AccountID != merged.ID {
		t.Fatalf("cached owner after merge=%+v %v", g, err)
	}
}

// Registration from another publishing node is authoritative even when the
// management handler has no locally connected tunnel to inspect.
func TestGrantInternalRPCCreationRejectsRemoteTCPAndUnknownProtocol(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	local := storage.NewLocalStorage(db)
	remote := ingressProxyStorage(t, local)
	ctx := context.Background()
	owner, err := remote.FindOrCreateByEmails(ctx, []string{"remote-protocol-owner@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	q := store.GrantCreate{AccountID: owner.ID, EndpointID: "remote", Label: "remote client", ExpiresAt: time.Now().Add(time.Hour), RequestLimit: 2}
	for _, protocol := range []string{"tcp", "", "unknown"} {
		var reg *storage.TunnelRegistration
		if protocol == "" {
			reg, err = remote.RegisterTunnel(ctx, "remote", owner.ID, "publishing-node")
		} else {
			reg, err = remote.RegisterEndpoint(ctx, "remote", owner.ID, "publishing-node", protocol)
		}
		if err != nil || !reg.Allowed {
			t.Fatalf("registration=%+v %v", reg, err)
		}
		if g, token, err := remote.CreateGrant(ctx, q); !errors.Is(err, store.ErrGrantScopeUnsupported) || g != nil || token != "" {
			t.Fatalf("unsupported protocol %q issued grant=%+v tokenExists=%v err=%v", protocol, g, token != "", err)
		}
		if list, err := remote.ListGrants(ctx, owner.ID, "remote"); err != nil || len(list) != 0 {
			t.Fatalf("unsupported protocol persisted grant=%+v err=%v", list, err)
		}
		if err := remote.UnregisterTunnel(ctx, "remote"); err != nil {
			t.Fatal(err)
		}
	}
	for _, protocol := range []string{"http", "mcp"} {
		if reg, err := remote.RegisterEndpoint(ctx, "remote", owner.ID, "publishing-node", protocol); err != nil || !reg.Allowed {
			t.Fatalf("supported registration=%+v %v", reg, err)
		}
		if g, token, err := remote.CreateGrant(ctx, q); err != nil || g == nil || token == "" {
			t.Fatalf("protocol %q grant failed: %+v %v", protocol, g, err)
		}
		if err := remote.UnregisterTunnel(ctx, "remote"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGrantRPCUsesNodeSecretBoundary(t *testing.T) {
	interceptor := nodeSecretInterceptor("test-secret")
	called := false
	_, err := interceptor(context.Background(), &internalv1.AdmitGrantRequest{}, &grpc.UnaryServerInfo{FullMethod: internalv1.LoginNodeDB_AdmitGrant_FullMethodName}, func(context.Context, interface{}) (interface{}, error) {
		called = true
		return &internalv1.AdmitGrantResponse{Allowed: true}, nil
	})
	if status.Code(err) != codes.Unauthenticated || called {
		t.Fatalf("unauthenticated grant RPC ran: called=%v err=%v", called, err)
	}
}
