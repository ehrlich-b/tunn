package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/inspection"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func accountTunnelRows(t *testing.T, f *webInspectorFixture, cookie *http.Cookie) []accountTunnel {
	t.Helper()
	response := f.call("GET", "/api/account/tunnels?account_id=ignored", nil, cookie, nil)
	if response.Code != 200 || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("list: %d %s", response.Code, response.Body)
	}
	var out struct {
		Tunnels  []accountTunnel
		Complete bool
	}
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil || !out.Complete {
		t.Fatalf("decode: %v %s", err, response.Body)
	}
	return out.Tunnels
}

// Real gRPC registration and disconnect, including remote storage and relay RPC.
func TestAccountTunnelsCrossNodeLifecycle(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	replica := securityReplicaStorage(t, f.local)
	remote := NewTunnelServer(f.p.config, nil, nil, replica)
	server := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor("live-tunnel-node")))
	pb.RegisterTunnelServiceServer(server, remote)
	internalpb.RegisterInternalServiceServer(server, NewInternalServer(remote, "relay.test", false))
	listener := prodAuthRPCListener{bufconn.Listen(1 << 20)}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	conn, err := grpc.NewClient("passthrough:///live-tunnel-relay", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := internalpb.NewInternalServiceClient(conn)
	if _, err := peer.ListAccountTunnels(context.Background(), &internalpb.ListAccountTunnelsRequest{AccountId: f.tunnel.AccountID}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("node gate: %v", err)
	}
	// Production peers attach the node credential through their transport.
	authenticated, err := grpc.NewClient("passthrough:///live-tunnel-relay", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, in, out any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoke(metadata.AppendToOutgoingContext(ctx, "x-node-secret", "live-tunnel-node"), method, in, out, cc, opts...)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer authenticated.Close()
	f.p.nodeClients = map[string]internalpb.InternalServiceClient{"relay": internalpb.NewInternalServiceClient(authenticated)}
	otherCookie := f.accountCookie(t, "other@example.com")
	other, _ := f.local.GetAccountByEmail(context.Background(), "other@example.com")
	remote.mu.Lock()
	remote.tunnels["other-secret"] = &TunnelConnection{TunnelID: "other-secret", AccountID: other.ID, CreatorEmail: other.PrimaryEmail, TargetURL: "http"}
	remote.mu.Unlock()
	if rows := accountTunnelRows(t, f, f.cookie); len(rows) != 1 || rows[0].Name != "api" {
		t.Fatalf("before connect: %+v", rows)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := pb.NewTunnelServiceClient(conn).EstablishTunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "live-worker", TargetUrl: "tcp", EndpointProtocol: "tcp", AuthToken: createTestJWT("owner@example.com", f.p.config.JWTSecret), TunnelKey: f.p.config.WellKnownKey, Capabilities: []string{common.CapabilityConnectionStreamV1}, ClientVersion: "1.2.3", ClientHost: "linux/amd64\n"}}}); err != nil {
		t.Fatal(err)
	}
	reply, err := stream.Recv()
	if err != nil || !reply.GetRegisterResponse().GetSuccess() {
		t.Fatalf("register: %v %v", reply, err)
	}
	rows := accountTunnelRows(t, f, f.cookie)
	if len(rows) != 2 || rows[1].Name != "live-worker" || rows[1].Kind != "TCP" || rows[1].ClientVersion != "1.2.3" || rows[1].ClientHost != "linux/amd64" || rows[1].ConnectedSince.IsZero() || rows[1].PublicURL != "https://live-worker.tunn.test" {
		t.Fatalf("connected: %+v", rows)
	}
	if rows := accountTunnelRows(t, f, otherCookie); len(rows) != 1 || rows[0].Name != "other-secret" {
		t.Fatalf("other owner: %+v", rows)
	}
	page := f.call("GET", "/account", nil, f.cookie, nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "live-worker") || strings.Contains(page.Body.String(), "other-secret") {
		t.Fatalf("page leaked or omitted tunnel: %d", page.Code)
	}
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := remote.GetTunnel("live-worker"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("disconnect did not remove publisher")
		}
		time.Sleep(time.Millisecond)
	}
	if rows := accountTunnelRows(t, f, f.cookie); len(rows) != 1 || rows[0].Name != "api" {
		t.Fatalf("after disconnect: %+v", rows)
	}
}

func TestAccountTunnelsAuthAndPrivacy(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	other := f.accountCookie(t, "other@example.com")
	for _, cookie := range []*http.Cookie{nil, {Name: authCookieName, Value: "forged"}} {
		page := f.call("GET", "/account", nil, cookie, nil)
		update := f.call("GET", "/api/account/tunnels", nil, cookie, nil)
		if page.Code != update.Code || update.Code == 200 || strings.Contains(update.Body.String(), "api.tunn.test") {
			t.Fatalf("auth mismatch page=%d update=%d", page.Code, update.Code)
		}
	}
	if rows := accountTunnelRows(t, f, other); len(rows) != 0 {
		t.Fatalf("other account: %+v", rows)
	}
	if w := f.call("POST", "/api/account/tunnels", nil, f.cookie, nil); w.Code != 405 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("GET", "https://unrelated.test/api/account/tunnels", nil)
	r.AddCookie(f.cookie)
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("host: %d", w.Code)
	}
	f.tunnel.Connected = time.Now().Add(-time.Hour)
	f.tunnel.ClientHost = "<img src=x onerror=alert(1)>"
	f.seed(t)
	rows := accountTunnelRows(t, f, f.cookie)
	if len(rows) != 1 || rows[0].LastRequest == nil || rows[0].LastRequest.Before(f.tunnel.Connected) {
		t.Fatalf("last request: %+v", rows)
	}
	page := f.call("GET", "/account", nil, f.cookie, nil)
	if strings.Contains(page.Body.String(), "<img src=x") || !strings.Contains(page.Body.String(), "&lt;img") {
		t.Fatal("client metadata rendered as HTML")
	}
}

type unavailableAccountTunnelPeer struct {
	internalpb.InternalServiceClient
}

func (unavailableAccountTunnelPeer) ListAccountTunnels(context.Context, *internalpb.ListAccountTunnelsRequest, ...grpc.CallOption) (*internalpb.ListAccountTunnelsResponse, error) {
	return nil, status.Error(codes.Unavailable, "offline")
}
func TestAccountTunnelsUnavailableRelay(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	f.p.nodeClients = map[string]internalpb.InternalServiceClient{"offline": unavailableAccountTunnelPeer{}}
	response := f.call("GET", "/api/account/tunnels", nil, f.cookie, nil)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"complete":false`) || !strings.Contains(response.Body.String(), `"name":"api"`) {
		t.Fatalf("partial: %d %s", response.Code, response.Body)
	}
	page := f.call("GET", "/account", nil, f.cookie, nil)
	if strings.Contains(page.Body.String(), "retrying automatically") || !strings.Contains(page.Body.String(), "1 online") {
		t.Fatal("available rows hidden or implementation copy shown")
	}
}

func TestAccountTunnelsAppAndMCP(t *testing.T) {
	p, tunnel, _ := appProxyFixture(t)
	// This fixture changes authority after constructing the tunnel server.
	p.tunnelServer.storage = p.storage
	rows, complete := p.accountTunnels(context.Background(), tunnel.AccountID)
	if !complete || len(rows) != 1 || rows[0].Name != "dashboard" || rows[0].Kind != "app" || rows[0].PublicURL != "https://dashboard.apps.example.com" {
		t.Fatalf("app: complete=%v rows=%+v", complete, rows)
	}
	p.tunnelServer.mu.Lock()
	p.tunnelServer.tunnels["connector"] = &TunnelConnection{TunnelID: "connector", TargetURL: "mcp", AccountID: tunnel.AccountID, Connected: time.Now()}
	p.tunnelServer.mu.Unlock()
	rows, complete = p.accountTunnels(context.Background(), tunnel.AccountID)
	if !complete || len(rows) != 2 || rows[0].Name != "connector" || rows[0].Kind != "MCP" || rows[0].PublicURL != "https://connector.tunn.test/mcp" {
		t.Fatalf("MCP: %+v", rows)
	}
}

func TestAccountTunnelsAccountMerge(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	secondCookie := f.accountCookie(t, "second@example.com")
	second, err := f.local.GetAccountByEmail(context.Background(), "second@example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.p.tunnelServer.tunnels["second-tunnel"] = &TunnelConnection{TunnelID: "second-tunnel", AccountID: second.ID, CreatorEmail: second.PrimaryEmail, Connected: time.Now()}
	merged, err := f.local.FindOrCreateByEmails(context.Background(), []string{"owner@example.com", "second@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range []*http.Cookie{f.cookie, secondCookie} {
		rows := accountTunnelRows(t, f, cookie)
		if len(rows) != 2 {
			t.Fatalf("merged account %s lost live connections: %+v", merged.ID, rows)
		}
	}
}

type accountTunnelDomains struct {
	domains.Backend
	rows []*domainpb.Domain
}

func (d accountTunnelDomains) List(context.Context, *domainpb.Owner) (*domainpb.DomainList, error) {
	return &domainpb.DomainList{Domains: d.rows}, nil
}

func TestAccountTunnelsAppDisplayNameDoesNotRebindURL(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	f.p.domains = accountTunnelDomains{rows: []*domainpb.Domain{
		{Name: "*.apps.example.com", State: "ready", VerifiedUntil: time.Now().Add(time.Hour).Unix(), AppNames: []*domainpb.AppName{{Label: "dashboard", Tunnel: "api"}}},
		{Name: "unrelated.example.com", State: "ready", VerifiedUntil: time.Now().Add(time.Hour).Unix(), Tunnel: "dashboard"},
		{Name: "*.other.example.com", State: "ready", VerifiedUntil: time.Now().Add(time.Hour).Unix(), AppNames: []*domainpb.AppName{{Label: "other-app", Tunnel: "dashboard"}}},
	}}
	rows, complete := f.p.accountTunnels(context.Background(), f.tunnel.AccountID)
	if !complete || len(rows) != 1 || rows[0].Name != "dashboard" || rows[0].PublicURL != "https://dashboard.apps.example.com" {
		t.Fatalf("display name rebound connection URL: %+v", rows)
	}
}

// Both the server-rendered page and update endpoint use activity order and the
// first page is bounded even before JavaScript runs.
func TestAccountTunnelsCompactInitialViewAndOrder(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	f.seed(t)
	// This connection has activity; all the alphabetically earlier idle ones
	// must follow it, ordered by name despite insertion and map iteration order.
	for i := 7; i >= 1; i-- {
		name := fmt.Sprintf("a-worker-%d", i)
		f.p.tunnelServer.tunnels[name] = &TunnelConnection{TunnelID: name, AccountID: f.tunnel.AccountID, TargetURL: "http", Connected: time.Now().Add(-2 * time.Hour)}
	}
	rows := accountTunnelRows(t, f, f.cookie)
	if len(rows) != 8 || rows[0].Name != "api" || rows[1].Name != "a-worker-1" || rows[7].Name != "a-worker-7" {
		t.Fatalf("activity/name order: %+v", rows)
	}
	// A newly active connection must move above the previously active one.
	time.Sleep(1100 * time.Millisecond) // Wire timestamps have one-second precision.
	recent := f.p.tunnelServer.tunnels["a-worker-7"]
	h, err := inspection.NewHistory()
	if err != nil {
		t.Fatal(err)
	}
	h.Begin("latest", "GET", "/health", nil, 0, 0).Finish(200, "text/plain", "complete")
	recent.inspector = h
	rows = accountTunnelRows(t, f, f.cookie)
	if rows[0].Name != "a-worker-7" || rows[1].Name != "api" {
		t.Fatalf("latest activity: %+v", rows)
	}
	page := f.call("GET", "/account", nil, f.cookie, nil)
	body := page.Body.String()
	if page.Code != 200 || !strings.Contains(body, "8 online") || !strings.Contains(body, "+4 more") || strings.Count(body, ` hidden><details>`) != 4 {
		t.Fatalf("compact initial view: %d %s", page.Code, body)
	}
	if strings.Contains(body, "Updates every") || strings.Contains(body, "Currently connected") || strings.Contains(body, "Connected since") {
		t.Fatal("initial view contains old status or metadata cards")
	}
	if rows[2].Duration() != "2h" || rows[2].URLStart()+rows[2].URLEnd() != rows[2].PublicURL {
		t.Fatalf("relative duration or URL: %+v", rows[2])
	}
}
