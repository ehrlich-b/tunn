package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type appDeviceTestAuthority struct {
	*LoginNodeDBServer
	unavailable atomic.Bool
	hung        atomic.Bool
}

func (s *appDeviceTestAuthority) AppDeviceCheck(ctx context.Context, in *internalpb.AppDeviceCheckRequest) (*internalpb.AppDeviceCheckResponse, error) {
	if s.unavailable.Load() {
		return nil, status.Error(codes.Unavailable, "fixture authority outage")
	}
	if s.hung.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.LoginNodeDBServer.AppDeviceCheck(ctx, in)
}
func appDeviceRemoteRelay(t *testing.T, f *appDeviceFixture) (*ProxyServer, *appDeviceTestAuthority) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	t.Cleanup(func() { listener.Close() })
	authority := &appDeviceTestAuthority{LoginNodeDBServer: &LoginNodeDBServer{storage: f.p.storage.(*storage.LocalStorage), appDevices: f.p.appDevices}}
	server := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor("fixture-app-node")))
	internalpb.RegisterLoginNodeDBServer(server, authority)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///app-devices-fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, in, out any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoke(metadata.NewOutgoingContext(ctx, metadata.Pairs("x-node-secret", "fixture-app-node")), method, in, out, cc, opts...)
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	p := &ProxyServer{Domain: f.p.Domain, config: f.p.config, tunnelServer: f.p.tunnelServer, storage: f.p.storage, meter: f.p.meter, domains: f.p.domains, quotaCache: NewQuotaCache(time.Minute), usageBuffer: NewUsageBuffer(), loginNodeConn: conn, tunnelCache: make(map[string]string)}
	return p, authority
}

func appDeviceIdleOrigin(t *testing.T, f *appDeviceFixture, token string) {
	t.Helper()
	f.tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityWebSocketV1: true}
	f.stream.hook = func(message *pb.TunnelMessage) error {
		if open := message.GetConnectionOpen(); open != nil {
			for name, value := range open.HttpRequest.Headers {
				if strings.EqualFold(name, "Tunn-Authorization") || strings.Contains(value, token) {
					t.Error("relay credential reached stream origin")
				}
			}
			if open.Protocol == "websocket" {
				if open.HttpRequest.Headers["Authorization"] != "Bearer upstream-only" {
					t.Error("upstream WS auth missing")
				}
				f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 101, Headers: map[string]string{"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}}}}})
			} else {
				f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/event-stream"}}}}})
				f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte(": ready\n\n")}}})
			}
		}
		return nil
	}
}

type appDeviceIdleStream struct {
	closed <-chan time.Time
	close  func()
}

func appDeviceSSE(t *testing.T, server *httptest.Server, token string) appDeviceIdleStream {
	t.Helper()
	req, _ := http.NewRequest("GET", server.URL+"/events", nil)
	req.Host = appDeviceTestHost
	req.Header.Set("Tunn-Authorization", "Bearer "+token)
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		t.Fatal("SSE admission", response.StatusCode)
	}
	first := make([]byte, len(": ready\n\n"))
	if _, err = io.ReadFull(response.Body, first); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	closed := make(chan time.Time, 1)
	go func() { io.Copy(io.Discard, response.Body); closed <- time.Now() }()
	t.Cleanup(func() { response.Body.Close() })
	return appDeviceIdleStream{closed, func() { response.Body.Close() }}
}
func appDeviceWS(t *testing.T, server *httptest.Server, token string) appDeviceIdleStream {
	t.Helper()
	cfg := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.NextProtos = []string{"http/1.1"}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", server.Listener.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", server.URL+"/socket", nil)
	req.Host = appDeviceTestHost
	req.Header.Set("Tunn-Authorization", "Bearer "+token)
	req.Header.Set("Authorization", "Bearer upstream-only")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if err = req.Write(conn); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		conn.Close()
		t.Fatal("WS admission", response.StatusCode)
	}
	closed := make(chan time.Time, 1)
	go func() {
		for {
			frame, err := fixtureReadFrame(reader, false)
			if err != nil || frame.opcode == 8 {
				closed <- time.Now()
				return
			}
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return appDeviceIdleStream{closed, func() { conn.Close() }}
}

func TestAppDeviceIdleStreamsEveryRelayRevocationAndOutage(t *testing.T) {
	for _, mutation := range []string{"device", "revoke-all", "mailbox", "suspension", "namespace", "resource", "share", "outage", "hung-authority"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAppDeviceFixture(t)
			var cookie *http.Cookie
			if mutation == "share" {
				cookie = appSessionCookie(t, f.p, "guest@example.com", "github", true, "")
				if _, err := f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: f.tunnel.AccountID, Endpoint: f.tunnel.TunnelID, ResourceId: f.tunnel.ResourceID, Email: "guest@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err != nil {
					t.Fatal(err)
				}
			}
			d, token := f.enroll(t, cookie)
			appDeviceIdleOrigin(t, f, token)
			first, authority := appDeviceRemoteRelay(t, f)
			second := &ProxyServer{Domain: f.p.Domain, config: f.p.config, tunnelServer: f.p.tunnelServer, storage: f.p.storage, meter: f.p.meter, domains: f.p.domains, quotaCache: NewQuotaCache(time.Minute), usageBuffer: NewUsageBuffer(), loginNodeConn: first.loginNodeConn, tunnelCache: make(map[string]string)}
			servers := []*httptest.Server{appDeviceTLSServer(t, first.createHandler()), appDeviceTLSServer(t, second.createHandler())}
			streams := []appDeviceIdleStream{}
			for _, server := range servers {
				streams = append(streams, appDeviceSSE(t, server, token), appDeviceWS(t, server, token))
			}
			var err error
			want := 403
			switch mutation {
			case "device":
				_, err = f.p.appDevices.revoke(context.Background(), d.Host, d.Account, d.ID, true)
				want = 401
			case "revoke-all":
				_, err = f.p.appDevices.revoke(context.Background(), d.Host, d.Account, "", true)
				want = 401
			case "mailbox":
				_, err = f.db.Exec(`DELETE FROM account_emails WHERE email=?`, d.Email)
			case "suspension":
				_, err = f.db.Exec(`INSERT INTO ops_account_state(account_id,state,version,reason,actor,changed_at) VALUES(?,'suspended',1,'fixture','fixture','2026-01-01T00:00:00Z') ON CONFLICT(account_id) DO UPDATE SET state='suspended',version=version+1`, d.Account)
			case "namespace":
				_, err = f.p.domains.Delete(context.Background(), &domainpb.Domain{Name: "*.apps.test", Owner: f.tunnel.AccountID})
			case "resource":
				_, err = f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: "replacement-owner", Endpoint: f.tunnel.TunnelID, Mode: "private"})
			case "share":
				_, err = f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "unshare", Owner: f.tunnel.AccountID, Endpoint: f.tunnel.TunnelID, ResourceId: f.tunnel.ResourceID, Email: d.Email})
			case "outage":
				authority.unavailable.Store(true)
				want = 503
			case "hung-authority":
				authority.hung.Store(true)
				want = 503
			}
			if err != nil {
				t.Fatal(err)
			}
			committed := time.Now()
			deadline := committed.Add(5 * time.Second)
			for n, stream := range streams {
				timer := time.NewTimer(time.Until(deadline))
				select {
				case closed := <-stream.closed:
					timer.Stop()
					elapsed := closed.Sub(committed)
					if elapsed > 5*time.Second {
						t.Fatalf("stream %d cutoff=%s", n, elapsed)
					}
					t.Logf("relay=%d transport=%s commit=%s cutoff_ms=%d", n/2, []string{"SSE", "WS"}[n%2], committed.UTC().Format(time.RFC3339Nano), elapsed.Milliseconds())
				case <-timer.C:
					t.Fatalf("stream %d survived 5 seconds", n)
				}
			}
			for _, relay := range []*ProxyServer{first, second} {
				w := appDeviceOpen(relay, appDeviceTestHost, token, nil)
				if w.Code != want {
					t.Fatalf("post-commit admission=%d want=%d", w.Code, want)
				}
			}
		})
	}
}

func TestAppDeviceClusterConcurrencyLeaseLimitAndFailClosed(t *testing.T) {
	f := newAppDeviceFixture(t)
	d, token := f.enroll(t, nil)
	relay, _ := appDeviceRemoteRelay(t, f)
	var leases []string
	for n := 0; n < 10; n++ {
		lease, _ := randomOAuthValue("al_")
		out, err := relay.checkAppDevice(context.Background(), &internalpb.AppDeviceCheckRequest{Operation: "acquire", TokenSha256: appDigest(token), Hostname: d.Host, Source: "192.0.2.1", LeaseId: lease})
		if err != nil || out.Status != 200 {
			t.Fatal("lease admission failed")
		}
		leases = append(leases, lease)
	}
	lease, _ := randomOAuthValue("al_")
	out, err := relay.checkAppDevice(context.Background(), &internalpb.AppDeviceCheckRequest{Operation: "acquire", TokenSha256: appDigest(token), Hostname: d.Host, Source: "192.0.2.2", LeaseId: lease})
	if err != nil || out.Status != 429 {
		t.Fatal("cluster stream limit not enforced")
	}
	if _, err = f.db.Exec(`UPDATE app_device_leases SET expires=0`); err != nil {
		t.Fatal(err)
	}
	out, err = relay.checkAppDevice(context.Background(), &internalpb.AppDeviceCheckRequest{Operation: "renew", TokenSha256: appDigest(token), Hostname: d.Host, Source: "192.0.2.1", DeviceId: d.ID, LeaseId: leases[0]})
	if err != nil || out.Status != 403 {
		t.Fatal("expired stream lease renewed")
	}
	if _, err = f.p.appDevices.revoke(context.Background(), d.Host, d.Account, d.ID, true); err != nil {
		t.Fatal(err)
	}
	// A fresh store instance reads the same durable committed authority.
	f.p.appDevices, err = newAppDeviceStore(f.db)
	if err != nil {
		t.Fatal(err)
	}
	out, err = f.p.checkAppDevice(context.Background(), &internalpb.AppDeviceCheckRequest{Operation: "resolve", TokenSha256: appDigest(token), Hostname: d.Host, Source: "192.0.2.1"})
	if err != nil || out.Status != 401 {
		t.Fatal("revocation not durable")
	}
}

func TestAppDeviceAuthorityRPCRequiresNodeSecret(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, token := f.enroll(t, nil)
	p, _ := appDeviceRemoteRelay(t, f)
	// Construct a second connection without the authenticated relay interceptor.
	// The production interceptor must reject it before the store can resolve data.
	listener := bufconn.Listen(1 << 20)
	defer listener.Close()
	g := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor("fixture-app-node")))
	internalpb.RegisterLoginNodeDBServer(g, &LoginNodeDBServer{appDevices: f.p.appDevices})
	go g.Serve(listener)
	defer g.Stop()
	conn, err := grpc.NewClient("passthrough:///untrusted-app-fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = internalpb.NewLoginNodeDBClient(conn).AppDeviceCheck(ctx, &internalpb.AppDeviceCheckRequest{Operation: "resolve", TokenSha256: appDigest(token), Hostname: appDeviceTestHost})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatal("unauthenticated node RPC accepted")
	}
	ipBlacklist.Lock()
	delete(ipBlacklist.entries, "bufconn")
	ipBlacklist.Unlock()
	if w := appDeviceOpen(p, appDeviceTestHost, token, nil); w.Code != 200 {
		t.Fatal("authenticated relay failed")
	}
}

func TestAppDeviceAccountHostFailureLimitUsesTrustedSource(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, token := f.enroll(t, nil)
	if _, err := f.db.Exec(`DELETE FROM account_emails WHERE email=?`, appDeviceTestEmail); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 30; n++ {
		r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
		r.RemoteAddr = net.JoinHostPort("192.0.2."+fmt.Sprint(n+1), "1234")
		r.Header.Set("Tunn-Authorization", "Bearer "+token)
		r.Header.Set("X-Forwarded-For", "spoof")
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("known-account failure status", n, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
	r.RemoteAddr = "198.51.100.1:4567"
	r.Header.Set("Tunn-Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal("account/hostname failure limit missing")
	}
}
