package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func oauthRPCFixture(t *testing.T, accountID string) store.OAuthCodeCreate {
	t.Helper()
	randomString := func() string {
		data := make([]byte, 32)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	challenge := sha256.Sum256([]byte("synthetic-verifier-0123456789012345678901234567890123456789"))
	return store.OAuthCodeCreate{Code: randomString(), ConsentID: randomString(), AccountID: accountID, EndpointID: "build", ClientID: "hosted-client", RedirectURI: "https://client.test/callback", Resource: "https://build.tunn.test/mcp", Scope: "mcp", CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), ExpiresAt: time.Now().Add(2 * time.Minute), GrantExpiresAt: time.Now().Add(time.Hour), RequestLimit: 5, Label: "synthetic hosted client"}
}
func oauthRPCExchange(q store.OAuthCodeCreate) store.OAuthCodeExchange {
	return store.OAuthCodeExchange{Code: q.Code, ClientID: q.ClientID, RedirectURI: q.RedirectURI, Resource: q.Resource, CodeChallenge: q.CodeChallenge}
}

func TestOAuthCodeInternalRPCPublisherOwnershipAndProtocol(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	local := storage.NewLocalStorage(db)
	remote := ingressProxyStorage(t, local)
	ctx := context.Background()
	owner, err := remote.FindOrCreateByEmails(ctx, []string{"oauth-rpc-owner@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	other, err := remote.FindOrCreateByEmails(ctx, []string{"oauth-rpc-other@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	q := oauthRPCFixture(t, owner.ID)
	if err := remote.CreateOAuthCode(ctx, q); !errors.Is(err, store.ErrOAuthInvalidGrant) {
		t.Fatalf("inactive publisher authorized=%v", err)
	}
	if reg, err := remote.RegisterEndpoint(ctx, "build", owner.ID, "publishing-node", "http"); err != nil || !reg.Allowed {
		t.Fatalf("register=%+v %v", reg, err)
	}
	wrongOwner := q
	wrongOwner.AccountID = other.ID
	if err := remote.CreateOAuthCode(ctx, wrongOwner); !errors.Is(err, store.ErrOAuthInvalidGrant) {
		t.Fatalf("non-owner authorized=%v", err)
	}
	if err := remote.CreateOAuthCode(ctx, q); err != nil {
		t.Fatal(err)
	}
	bad := oauthRPCExchange(q)
	bad.Resource = "https://other.tunn.test/mcp"
	if g, token, err := remote.ExchangeOAuthCode(ctx, bad); !errors.Is(err, store.ErrOAuthInvalidGrant) || g != nil || token != "" {
		t.Fatal("wrong resource minted")
	}
	for _, registration := range []struct{ owner, protocol string }{{owner.ID, "tcp"}, {owner.ID, ""}, {other.ID, "http"}} {
		if err := remote.UnregisterTunnel(ctx, "build"); err != nil {
			t.Fatal(err)
		}
		if reg, err := remote.RegisterEndpoint(ctx, "build", registration.owner, "publishing-node", registration.protocol); err != nil || !reg.Allowed {
			t.Fatalf("register=%+v %v", reg, err)
		}
		if g, token, err := remote.ExchangeOAuthCode(ctx, oauthRPCExchange(q)); !errors.Is(err, store.ErrOAuthInvalidGrant) || g != nil || token != "" {
			t.Fatalf("replacement publisher minted: %+v %v", g, err)
		}
		if list, err := remote.ListGrants(ctx, owner.ID, ""); err != nil || len(list) != 0 {
			t.Fatalf("failed exchange minted=%+v %v", list, err)
		}
		if err := remote.CreateOAuthCode(ctx, oauthRPCFixture(t, owner.ID)); !errors.Is(err, store.ErrOAuthInvalidGrant) {
			t.Fatalf("unsupported owner/protocol code accepted=%v", err)
		}
	}
	if err := remote.UnregisterTunnel(ctx, "build"); err != nil {
		t.Fatal(err)
	}
	if reg, err := remote.RegisterEndpoint(ctx, "build", owner.ID, "publishing-node", "http"); err != nil || !reg.Allowed {
		t.Fatalf("restore=%+v %v", reg, err)
	}
	g, token, err := remote.ExchangeOAuthCode(ctx, oauthRPCExchange(q))
	if err != nil || g == nil || g.AccountID != owner.ID || token == "" {
		t.Fatalf("RPC exchange=%+v %v", g, err)
	}
	out, err := remote.AdmitGrant(ctx, store.GrantAdmissionRequest{AccountID: owner.ID, EndpointID: "build", Token: token, RequestID: "oauth-rpc-call"})
	if err != nil || !out.Allowed || out.GrantID != g.ID {
		t.Fatalf("OAuth token unusable=%+v %v", out, err)
	}
	if _, _, err := remote.ExchangeOAuthCode(ctx, oauthRPCExchange(q)); !errors.Is(err, store.ErrOAuthInvalidGrant) {
		t.Fatalf("RPC exchange replay=%v", err)
	}
	malformed := oauthRPCFixture(t, owner.ID)
	malformed.CodeChallenge = "bad"
	if err := remote.CreateOAuthCode(ctx, malformed); !errors.Is(err, store.ErrOAuthInvalidRequest) {
		t.Fatalf("malformed OAuth request=%v", err)
	}
	remote.SetConnection(nil)
	if g, token, err := remote.ExchangeOAuthCode(ctx, oauthRPCExchange(q)); !errors.Is(err, storage.ErrNotAvailable) || g != nil || token != "" {
		t.Fatal("unavailable code storage minted")
	}
	if err := remote.CreateOAuthCode(ctx, q); !errors.Is(err, storage.ErrNotAvailable) {
		t.Fatal("unavailable code storage authorized")
	}
}

func TestOAuthCodeInternalRPCMergedCachedOwner(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	local := storage.NewLocalStorage(db)
	remote := ingressProxyStorage(t, local)
	ctx := context.Background()
	old, err := remote.FindOrCreateByEmails(ctx, []string{"oauth-rpc-old@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if reg, err := remote.RegisterEndpoint(ctx, "build", old.ID, "publishing-node", "http"); err != nil || !reg.Allowed {
		t.Fatalf("register=%+v %v", reg, err)
	}
	q := oauthRPCFixture(t, old.ID)
	if err := remote.CreateOAuthCode(ctx, q); err != nil {
		t.Fatal(err)
	}
	next, err := remote.FindOrCreateByEmails(ctx, []string{"oauth-rpc-next@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.UpdatePlan(ctx, next.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	merged, err := remote.FindOrCreateByEmails(ctx, []string{old.PrimaryEmail, next.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	g, _, err := remote.ExchangeOAuthCode(ctx, oauthRPCExchange(q))
	if err != nil || g == nil || g.AccountID != merged.ID {
		t.Fatalf("cached owner exchange failed=%+v %v", g, err)
	}
	if err := remote.CreateOAuthCode(ctx, oauthRPCFixture(t, merged.ID)); err != nil {
		t.Fatalf("merged owner cannot consent=%v", err)
	}
}

func TestOAuthCodeRPCNodeSecretBoundary(t *testing.T) {
	for _, method := range []string{internalv1.LoginNodeDB_CreateOAuthCode_FullMethodName, internalv1.LoginNodeDB_ExchangeOAuthCode_FullMethodName} {
		called := false
		_, err := nodeSecretInterceptor("synthetic-node-secret")(context.Background(), &internalv1.CreateOAuthCodeRequest{}, &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, interface{}) (interface{}, error) {
			called = true
			return &internalv1.CreateOAuthCodeResponse{}, nil
		})
		if status.Code(err) != codes.Unauthenticated || called {
			t.Fatalf("unauthenticated OAuth RPC ran: called=%v err=%v", called, err)
		}
	}
}

func TestOAuthCodeRPCBlankConfiguredSecretFailsClosed(t *testing.T) {
	for _, method := range []string{internalv1.LoginNodeDB_CreateOAuthCode_FullMethodName, internalv1.LoginNodeDB_ExchangeOAuthCode_FullMethodName} {
		for _, values := range [][]string{nil, {""}, {"synthetic-node-secret"}} {
			md := metadata.MD{}
			if values != nil {
				md["x-node-secret"] = values
			}
			ctx := metadata.NewIncomingContext(context.Background(), md)
			called := false
			_, err := nodeSecretInterceptor("")(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, interface{}) (interface{}, error) {
				called = true
				return nil, nil
			})
			if status.Code(err) != codes.Unauthenticated || called {
				t.Fatalf("blank configured secret admitted RPC: called=%v err=%v", called, err)
			}
		}
	}
}
