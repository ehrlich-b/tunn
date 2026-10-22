package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/storage"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type inventoryStorage struct {
	mockStorage
	accounts map[string]*storage.Account
	errors   map[string]error
}

func (s *inventoryStorage) GetAccount(_ context.Context, id string) (*storage.Account, error) {
	return s.accounts[id], s.errors[id]
}

func TestAccountInventoryDeletedOwner(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	f.p.tunnelServer.storage = &inventoryStorage{accounts: map[string]*storage.Account{
		f.tunnel.AccountID: {ID: f.tunnel.AccountID},
	}}
	f.p.tunnelServer.tunnels["deleted-secret"] = &TunnelConnection{TunnelID: "deleted-secret", AccountID: "deleted-account"}
	out, err := NewInternalServer(f.p.tunnelServer, "", false).ListAccountTunnels(context.Background(), &internalpb.ListAccountTunnelsRequest{AccountId: f.tunnel.AccountID})
	if err != nil || out.GetPartial() || len(out.GetTunnels()) != 1 || out.Tunnels[0].Name != "api" {
		t.Fatalf("healthy inventory lost to deleted unrelated owner: rows=%v err=%v", out, err)
	}
}

func TestAccountInventoryOwnerAuthority(t *testing.T) {
	for _, tc := range []struct {
		name    string
		queried bool
		missing bool
	}{
		{name: "unrelated-outage"}, {name: "queried-owner-outage", queried: true}, {name: "queried-owner-deleted", queried: true, missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWebInspectorFixture(t, 0, 0)
			authority := &inventoryStorage{accounts: map[string]*storage.Account{
				f.tunnel.AccountID: {ID: f.tunnel.AccountID},
				"other":            {ID: "other"},
				"merged":           {ID: f.tunnel.AccountID},
			}, errors: map[string]error{}}
			failing := "uncertain"
			if tc.queried {
				failing = f.tunnel.AccountID
			}
			if tc.missing {
				delete(authority.accounts, failing)
			} else {
				authority.errors[failing] = errors.New("authority offline")
			}
			f.p.tunnelServer.storage = authority
			for _, id := range []string{"other", "merged", "uncertain", ""} {
				f.p.tunnelServer.tunnels[id] = &TunnelConnection{TunnelID: id + "-secret", AccountID: id}
			}
			out, err := NewInternalServer(f.p.tunnelServer, "", false).ListAccountTunnels(context.Background(), &internalpb.ListAccountTunnelsRequest{AccountId: f.tunnel.AccountID})
			if tc.queried {
				if status.Code(err) != codes.Unavailable || len(out.GetTunnels()) != 0 {
					t.Fatalf("unproven owner: %v %v", out, err)
				}
				rows, complete := f.p.accountTunnels(context.Background(), f.tunnel.AccountID)
				if complete || len(rows) != 0 {
					t.Fatalf("owner outage labeled complete: %v %v", complete, rows)
				}
			} else {
				if err != nil || !out.GetPartial() || len(out.GetTunnels()) != 2 {
					t.Fatalf("partial ownership: %v %v", out, err)
				}
				for _, row := range out.Tunnels {
					if row.Name != "api" && row.Name != "merged-secret" {
						t.Fatalf("cross-account leak: %v", row)
					}
				}
				rows, complete := f.p.accountTunnels(context.Background(), f.tunnel.AccountID)
				if complete || len(rows) != 2 {
					t.Fatalf("partial lost across RPC: %v %v", complete, rows)
				}
			}
		})
	}
}

type inventoryPeer struct {
	internalpb.InternalServiceClient
	rows    []*internalpb.AccountTunnel
	slow    bool
	partial bool
}

func (p inventoryPeer) ListAccountTunnels(ctx context.Context, _ *internalpb.ListAccountTunnelsRequest, _ ...grpc.CallOption) (*internalpb.ListAccountTunnelsResponse, error) {
	if p.slow {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &internalpb.ListAccountTunnelsResponse{Tunnels: p.rows, Partial: p.partial}, nil
}

type inventoryDomains struct {
	domains.Backend
	wantOwner string
	fail      bool
	started   chan struct{}
}

func (d inventoryDomains) List(ctx context.Context, owner *domainpb.Owner) (*domainpb.DomainList, error) {
	if d.started != nil {
		close(d.started)
	}
	if owner.Owner != d.wantOwner {
		return nil, errors.New("cross-account domain query")
	}
	if d.fail {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &domainpb.DomainList{Domains: []*domainpb.Domain{{Name: "dashboard.example.test", Tunnel: "api", State: "ready", VerifiedUntil: time.Now().Add(time.Hour).Unix()}}}, nil
}

func TestAccountInventorySlowPeerAndDomains(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("domain-outage-", fail), func(t *testing.T) {
			f := newWebInspectorFixture(t, 0, 0)
			started := make(chan struct{})
			f.p.domains = inventoryDomains{wantOwner: f.tunnel.AccountID, fail: fail, started: started}
			f.p.nodeClients = map[string]internalpb.InternalServiceClient{
				"slow":    inventoryPeer{slow: true},
				"healthy": inventoryPeer{rows: []*internalpb.AccountTunnel{{Name: "peer-worker", Kind: "HTTP", PublicUrl: "https://peer-worker.tunn.test"}}},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			rows, complete := f.p.accountTunnels(ctx, f.tunnel.AccountID)
			if complete || len(rows) != 2 {
				t.Fatalf("healthy rows erased by slow peer: complete=%v rows=%+v", complete, rows)
			}
			select {
			case <-started:
			default:
				t.Fatal("enrichment never started")
			}
			want := "https://dashboard.example.test"
			if fail {
				want = "https://api.tunn.test"
			}
			if rows[0].PublicURL != want {
				t.Fatalf("domain enrichment lost: %+v", rows)
			}
		})
	}
}

func TestAccountInventoryDuplicateName(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	f.p.nodeClients = map[string]internalpb.InternalServiceClient{
		"new": inventoryPeer{rows: []*internalpb.AccountTunnel{nil, {Name: "api", Kind: "MCP", PublicUrl: "https://api.tunn.test/mcp", ConnectedSinceUnix: time.Now().Add(time.Hour).Unix()}}},
		"old": inventoryPeer{rows: []*internalpb.AccountTunnel{{Name: "api", PublicUrl: "https://old.tunn.test", ConnectedSinceUnix: 1}}},
	}
	for i := 0; i < 20; i++ {
		rows, complete := f.p.accountTunnels(context.Background(), f.tunnel.AccountID)
		if !complete || len(rows) != 1 || rows[0].Kind != "MCP" || rows[0].PublicURL != "https://api.tunn.test/mcp" {
			t.Fatalf("duplicate reconnect selection: %v %+v", complete, rows)
		}
	}
}

func TestAccountInventoryRPCPartial(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	authority := &inventoryStorage{accounts: map[string]*storage.Account{f.tunnel.AccountID: {ID: f.tunnel.AccountID}}, errors: map[string]error{"uncertain": errors.New("unavailable")}}
	remote := NewTunnelServer(f.p.config, nil, nil, authority)
	remote.tunnels["api"] = f.tunnel
	remote.tunnels["unproven"] = &TunnelConnection{TunnelID: "private-other-account", AccountID: "uncertain"}
	server := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor("inventory-secret")))
	internalpb.RegisterInternalServiceServer(server, NewInternalServer(remote, "", false))
	listener := prodAuthRPCListener{bufconn.Listen(1 << 20)}
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	defer listener.Close()
	conn, err := grpc.NewClient("passthrough:///inventory", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := internalpb.NewInternalServiceClient(conn)
	request := &internalpb.ListAccountTunnelsRequest{AccountId: f.tunnel.AccountID}
	if _, err := peer.ListAccountTunnels(context.Background(), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("node gate: %v", err)
	}
	authenticated, err := grpc.NewClient("passthrough:///inventory", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, in, out any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoke(metadata.AppendToOutgoingContext(ctx, "x-node-secret", "inventory-secret"), method, in, out, cc, opts...)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer authenticated.Close()
	peer = internalpb.NewInternalServiceClient(authenticated)
	ctx := context.Background()
	out, err := peer.ListAccountTunnels(ctx, request)
	if err != nil || !out.GetPartial() || len(out.GetTunnels()) != 1 || out.Tunnels[0].Name != "api" {
		t.Fatalf("partial wire response: %v %v", out, err)
	}
	// The aggregator must carry the wire flag into the authenticated JSON API.
	f.p.nodeClients = map[string]internalpb.InternalServiceClient{"partial": peer}
	rows, complete := f.p.accountTunnels(ctx, f.tunnel.AccountID)
	if complete || len(rows) != 1 {
		t.Fatalf("partial status lost: %v %+v", complete, rows)
	}
	response := f.call("GET", "/api/account/tunnels", nil, f.cookie, nil)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"complete":false`) || strings.Contains(response.Body.String(), "private-other-account") {
		t.Fatalf("API ownership status: %d %s", response.Code, response.Body)
	}
}
