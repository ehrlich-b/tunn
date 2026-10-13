package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/metering"
	ipb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type permissionSharingAuthority struct {
	*metering.Store
	sharing metering.SharingBackend
	stalled atomic.Bool
}

func (b *permissionSharingAuthority) Sharing(ctx context.Context, r *mp.SharingRequest) (*mp.SharingResponse, error) {
	if b.stalled.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return b.sharing.Sharing(ctx, r)
}

type publisherPermissionFixture struct {
	b           *ProxyServer
	ledger      *metering.Store
	db          *sql.DB
	authority   *permissionSharingAuthority
	relay       *httptest.Server
	tunnel      *TunnelConnection
	connections atomic.Int32
	originHits  atomic.Int32
}

func newPublisherPermissionFixture(t *testing.T) *publisherPermissionFixture {
	t.Helper()
	f := newMCPOAuthFixture(t)
	b := f.p
	b.config.NodeSecret = "fixture-cluster"
	b.config.Insecure = true
	stack := &publisherPermissionFixture{b: b, ledger: b.meter.(*metering.Store), db: b.mcpOAuth.db}
	stack.authority = &permissionSharingAuthority{Store: stack.ledger, sharing: b.meter.(metering.SharingBackend)}
	b.meter = stack.authority
	b.tunnelServer.sharing = stack.authority
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stack.originHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: "+strings.Repeat("x", 1024)+"\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	gs := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor(b.config.NodeSecret)))
	pb.RegisterTunnelServiceServer(gs, b.tunnelServer)
	b.grpcServer = gs
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sibling" {
			_, _ = io.WriteString(w, "healthy")
			return
		}
		b.createHandler().ServeHTTP(w, r)
	})
	relay := httptest.NewUnstartedServer(b.createHTTP2Router(routes))
	relay.EnableHTTP2 = true
	relay.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			stack.connections.Add(1)
		}
	}
	relay.StartTLS()
	stack.relay = relay
	server := NewInternalServer(b.tunnelServer, relay.Listener.Addr().String(), false)
	server.proxy = b
	ipb.RegisterInternalServiceServer(gs, server)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	publisher := &client.ServeClient{TunnelID: "stream-lifetime", TargetURL: origin.URL, ServerAddr: relay.Listener.Addr().String(), AuthToken: relayJWT(t, b, "owner@example.com"), TunnelKey: b.config.WellKnownKey, RequireSharing: true, Insecure: true, Quiet: true, OnRegistered: func(u string) { ready <- u }}
	go func() { done <- publisher.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("publisher cleanup exceeded bound")
		}
		gs.Stop()
		relay.Close()
		origin.Close()
	})
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("publisher registration")
	}
	stack.tunnel, _ = b.tunnelServer.GetTunnel(publisher.TunnelID)
	if stack.tunnel == nil || stack.tunnel.ResourceID == "" {
		t.Fatal("publisher lost sharing resource")
	}
	_, err := stack.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: stack.tunnel.AccountID, Endpoint: stack.tunnel.TunnelID, Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	return stack
}
func (f *publisherPermissionFixture) frontend(t *testing.T) *ProxyServer {
	t.Helper()
	a := securityProxy(f.b.storage)
	a.config.Insecure = true
	a.config.NodeSecret = f.b.config.NodeSecret
	pool := x509.NewCertPool()
	pool.AddCert(f.relay.Certificate())
	conn, err := grpc.NewClient("passthrough:///"+f.relay.Listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool})), grpc.WithPerRPCCredentials(&nodeSecretCreds{secret: a.config.NodeSecret}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	a.nodeClients = map[string]ipb.InternalServiceClient{"publisher": ipb.NewInternalServiceClient(conn)}
	return a
}
func (f *publisherPermissionFixture) revoke(t *testing.T, outage bool) time.Time {
	t.Helper()
	if outage {
		f.authority.stalled.Store(true)
		return time.Now()
	}
	_, err := f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "unshare", Owner: f.tunnel.AccountID, Endpoint: f.tunnel.TunnelID, Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	return time.Now()
}
func (f *publisherPermissionFixture) assertClean(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.tunnel.pendingMu.RLock()
		pending := len(f.tunnel.pendingStreams)
		f.tunnel.pendingMu.RUnlock()
		var events, unfinished int
		if err := f.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(CASE WHEN finished=0 THEN 1 ELSE 0 END),0) FROM meter_events WHERE endpoint=?`, f.tunnel.TunnelID).Scan(&events, &unfinished); err != nil {
			t.Fatal(err)
		}
		if pending == 0 && f.b.operations.active.Load() == 0 && events == 1 && unfinished == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending=%d active=%d events=%d unfinished=%d", pending, f.b.operations.active.Load(), events, unfinished)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type permissionMarkedConn struct {
	net.Conn
	blocked chan struct{}
	once    sync.Once
}

func (c *permissionMarkedConn) Write(b []byte) (int, error) {
	if bytes.Contains(b, []byte("data: ")) {
		c.once.Do(func() { close(c.blocked) })
	}
	return c.Conn.Write(b)
}
func (c *permissionMarkedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 44), Port: 4321}
}
func TestPublisherStreamActualTransportStalledReader(t *testing.T) {
	for _, frontend := range []bool{false, true} {
		for _, outage := range []bool{false, true} {
			name := map[bool]string{false: "publisher-relay", true: "frontend-relay"}[frontend] + "/" + map[bool]string{false: "revocation", true: "authority-timeout"}[outage]
			t.Run(name, func(t *testing.T) {
				f := newPublisherPermissionFixture(t)
				var a *ProxyServer
				if frontend {
					a = f.frontend(t)
				}
				serverConn, clientConn := net.Pipe()
				defer clientConn.Close()
				marked := &permissionMarkedConn{Conn: serverConn, blocked: make(chan struct{})}
				listener := &permissionPipeListener{conn: marked, closed: make(chan struct{})}
				done := make(chan struct{})
				srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(done)
					if frontend {
						a.proxyToNode(w, r, f.relay.Listener.Addr().String(), f.tunnel.TunnelID)
					} else {
						f.b.createHandler().ServeHTTP(w, r)
					}
				})}
				defer srv.Close()
				go func() { _ = srv.Serve(listener) }()
				_, err := io.WriteString(clientConn, "GET /events HTTP/1.1\r\nHost: stream-lifetime.tunn.test\r\nAuthorization: Bearer "+relayJWT(t, f.b, "alice@example.com")+"\r\n\r\n")
				if err != nil {
					t.Fatal(err)
				}
				_ = clientConn.SetReadDeadline(time.Now().Add(4 * time.Second))
				response, err := http.ReadResponse(bufio.NewReader(permissionByteReader{clientConn}), nil)
				if err != nil || response.StatusCode != 200 {
					t.Fatalf("stream admission: error=%v response=%v", err, response)
				}
				select {
				case <-marked.blocked:
				case <-time.After(3 * time.Second):
					t.Fatal("publisher response did not reach downstream backpressure")
				}
				committed := f.revoke(t, outage)
				select {
				case <-done:
					t.Logf("committed authority change to relay cutoff: %s", time.Since(committed))
				case <-time.After(4 * time.Second):
					t.Fatal("relay transport cutoff exceeded 4 seconds")
				}
				f.assertClean(t)
			})
		}
	}
}
func TestPublisherStreamHTTP2SiblingAndAccounting(t *testing.T) {
	f := newPublisherPermissionFixture(t)
	h := f.relay.Client()
	h.Timeout = 6 * time.Second
	r, _ := http.NewRequest("GET", f.relay.URL+"/events", nil)
	r.Host = "stream-lifetime.tunn.test"
	r.Header.Set("Authorization", "Bearer "+relayJWT(t, f.b, "alice@example.com"))
	response, err := h.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("stream status %d: %s", response.StatusCode, data)
	}
	if response.ProtoMajor != 2 {
		t.Fatal("HTTP/2 required")
	}
	chunk := make([]byte, len("data: ")+1024+2)
	if _, err = io.ReadFull(response.Body, chunk); err != nil {
		t.Fatal(err)
	}
	count := f.connections.Load()
	committed := f.revoke(t, false)
	if _, err = response.Body.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked stream remained open")
	}
	if time.Since(committed) > 4*time.Second {
		t.Fatal("HTTP/2 cutoff exceeded bound")
	}
	sibling, err := h.Get(f.relay.URL + "/sibling")
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Body.Close()
	data, err := io.ReadAll(sibling.Body)
	if err != nil || string(data) != "healthy" || f.connections.Load() != count {
		t.Fatal("HTTP/2 sibling connection changed", err)
	}
	f.assertClean(t)
}

type permissionMeterAuthority struct {
	*metering.Store
	sharing          metering.SharingBackend
	entered, release chan struct{}
	once             sync.Once
	request          bool
}

func (b *permissionMeterAuthority) Sharing(ctx context.Context, in *mp.SharingRequest) (*mp.SharingResponse, error) {
	return b.sharing.Sharing(ctx, in)
}
func (b *permissionMeterAuthority) Charge(ctx context.Context, in *mp.ChargeRequest) (*mp.Decision, error) {
	if b.request && in.RequestBytes > 0 || !b.request && in.ResponseBytes > 0 {
		b.once.Do(func() { close(b.entered) })
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-b.release:
			return nil, context.Canceled
		}
	}
	return b.Store.Charge(ctx, in)
}
func TestPublisherStreamCancelledMeterAuthority(t *testing.T) {
	f := newPublisherPermissionFixture(t)
	authority := &permissionMeterAuthority{Store: f.ledger, sharing: f.authority, entered: make(chan struct{}), release: make(chan struct{})}
	defer close(authority.release)
	f.b.meter = authority
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	listener := &permissionPipeListener{conn: &permissionMarkedConn{Conn: serverConn, blocked: make(chan struct{})}, closed: make(chan struct{})}
	done := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(done); f.b.createHandler().ServeHTTP(w, r) })}
	defer srv.Close()
	go func() { _ = srv.Serve(listener) }()
	_, err := io.WriteString(clientConn, "GET /events HTTP/1.1\r\nHost: stream-lifetime.tunn.test\r\nAuthorization: Bearer "+relayJWT(t, f.b, "alice@example.com")+"\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(4 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(permissionByteReader{clientConn}), nil)
	if err != nil || response.StatusCode != 200 {
		t.Fatal("stream headers", err)
	}
	select {
	case <-authority.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("response charge did not start")
	}
	committed := f.revoke(t, false)
	select {
	case <-done:
		t.Logf("revocation during stalled charge to cutoff: %s", time.Since(committed))
	case <-time.After(4 * time.Second):
		t.Fatal("metering delayed transport cutoff")
	}
	f.assertClean(t)
}
func TestPublisherStreamCancelledUploadRetainsAccounting(t *testing.T) {
	f := newMCPOAuthFixture(t)
	ledger := f.p.meter.(*metering.Store)
	authority := &permissionMeterAuthority{Store: ledger, sharing: ledger, entered: make(chan struct{}), release: make(chan struct{}), request: true}
	f.p.meter = authority
	s := newIngressMeter(f.p, f.tunnel)
	w := &meterResponseWriter{ResponseWriter: httptest.NewRecorder(), meter: s, status: 200}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "https://tools.tunn.test/", nil)
	if !s.admit(ctx, w, r) {
		t.Fatal("meter admission")
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = s.charge(ctx, true, 1024); s.complete(ctx, w) }()
	select {
	case <-authority.entered:
	case <-time.After(time.Second):
		t.Fatal("request charge did not start")
	}
	cancel()
	start := time.Now()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancelled upload charge did not stop")
	}
	used, err := f.p.storage.GetMonthlyUsage(context.Background(), f.tunnel.AccountID)
	if err != nil || used != 1024 {
		t.Fatalf("already-read request bytes: used=%d error=%v", used, err)
	}
	if f.p.operations.drops.Load() == 0 {
		t.Fatal("failed authority reconciliation was not recorded")
	}
	t.Logf("cancelled upload reconciliation: %s; retained bytes=%d", time.Since(start), used)
}

func TestPublisherStreamPreflightDenialsKeepAuthAndAudit(t *testing.T) {
	for _, bearer := range []string{"", "Bearer invalid-fixture"} {
		t.Run(map[bool]string{false: "browser-login", true: "invalid-bearer"}[bearer != ""], func(t *testing.T) {
			f := newPublisherPermissionFixture(t)
			a := f.frontend(t)
			r := httptest.NewRequest("GET", "https://stream-lifetime.tunn.test/events", nil)
			if bearer != "" {
				r.Header.Set("Authorization", bearer)
			}
			w := httptest.NewRecorder()
			a.proxyToNode(w, r, f.relay.Listener.Addr().String(), f.tunnel.TunnelID)
			if bearer == "" {
				if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "https://tunn.test/auth/login?") {
					t.Fatal("browser sign-in response", w.Code)
				}
			} else {
				if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
					t.Fatal("bearer challenge response", w.Code)
				}
			}
			if f.originHits.Load() != 0 || w.Header().Get("Tunn-Request-ID") == "" {
				t.Fatal("preflight dispatch or missing denial audit")
			}
			f.assertClean(t)
		})
	}
}
