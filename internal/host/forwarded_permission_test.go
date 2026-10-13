package host

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ipb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc"
)

type forwardPermissionPeer struct {
	ipb.InternalServiceClient
	server  *InternalServer
	stalled *atomic.Bool
}

func (c forwardPermissionPeer) CheckForwardedPermission(ctx context.Context, r *ipb.ForwardedPermissionRequest, _ ...grpc.CallOption) (*ipb.ForwardedPermissionResponse, error) {
	if c.stalled != nil && c.stalled.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return c.server.CheckForwardedPermission(ctx, r)
}
func (c forwardPermissionPeer) FindTunnel(ctx context.Context, r *ipb.FindTunnelRequest, _ ...grpc.CallOption) (*ipb.FindTunnelResponse, error) {
	return c.server.FindTunnel(ctx, r)
}

type stalledForwardWriter struct {
	header            http.Header
	started, released chan struct{}
	begin, release    sync.Once
}

func (w *stalledForwardWriter) Header() http.Header { return w.header }
func (w *stalledForwardWriter) WriteHeader(int)     {}
func (w *stalledForwardWriter) Flush()              {}
func (w *stalledForwardWriter) Write([]byte) (int, error) {
	w.begin.Do(func() { close(w.started) })
	<-w.released
	return 0, io.ErrClosedPipe
}
func (w *stalledForwardWriter) SetWriteDeadline(time.Time) error {
	w.release.Do(func() { close(w.released) })
	return nil
}

func TestForwardedPermissionStalledWriterCutoff(t *testing.T) {
	b, tunnel, ledger, _ := webSharingFixture(t)
	_, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "data: finite fixture\n\n")
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()
	a := securityProxy(b.storage)
	a.config.Insecure = true
	a.config.NodeSecret = "fixture-cluster"
	addr := strings.TrimPrefix(upstream.URL, "https://")
	authority := NewInternalServer(b.tunnelServer, addr, false)
	authority.proxy = b
	a.nodeClients = map[string]ipb.InternalServiceClient{"publisher": forwardPermissionPeer{server: authority}}
	r := httptest.NewRequest("GET", "https://api.tunn.test/events", nil)
	r.Header.Set("Authorization", "Bearer "+relayJWT(t, b, "alice@example.com"))
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	w := &stalledForwardWriter{header: make(http.Header), started: make(chan struct{}), released: make(chan struct{})}
	defer w.SetWriteDeadline(time.Now())
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = recover() }()
		a.proxyToNode(w, r, addr, tunnel.TunnelID)
	}()
	select {
	case <-w.started:
	case <-time.After(3 * time.Second):
		t.Fatal("first-hop write did not start")
	}
	start := time.Now()
	_, err = ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "unshare", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Logf("authority commit to first-hop cutoff: %s", time.Since(start))
	case <-time.After(4 * time.Second):
		t.Fatal("first-hop writer did not stop within 4 seconds")
	}
}

type permissionPipeListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
}

func (l *permissionPipeListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *permissionPipeListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return l.conn.Close()
}
func (l *permissionPipeListener) Addr() net.Addr { return l.conn.LocalAddr() }

type permissionByteReader struct{ io.Reader }

func (r permissionByteReader) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.Reader.Read(b)
}

func TestForwardedPermissionTwoRelayStalledReader(t *testing.T) {
	for _, outage := range []bool{false, true} {
		t.Run(map[bool]string{false: "revocation", true: "authority-timeout"}[outage], func(t *testing.T) {
			b, tunnel, ledger, _ := webSharingFixture(t)
			_, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
			if err != nil {
				t.Fatal(err)
			}
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+strings.Repeat("x", 1024)+"\n\n")
				w.(http.Flusher).Flush()
			}))
			defer upstream.Close()
			a := securityProxy(b.storage)
			a.config.Insecure = true
			a.config.NodeSecret = "fixture-cluster"
			addr := strings.TrimPrefix(upstream.URL, "https://")
			authority := NewInternalServer(b.tunnelServer, addr, false)
			authority.proxy = b
			stalled := &atomic.Bool{}
			a.nodeClients = map[string]ipb.InternalServiceClient{"publisher": forwardPermissionPeer{server: authority, stalled: stalled}}
			serverConn, clientConn := net.Pipe()
			defer clientConn.Close()
			listener := &permissionPipeListener{conn: serverConn, closed: make(chan struct{})}
			done := make(chan struct{})
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				a.proxyToNode(w, r, addr, tunnel.TunnelID)
			})}
			defer srv.Close()
			go func() { _ = srv.Serve(listener) }()
			token := relayJWT(t, b, "alice@example.com")
			if _, err = io.WriteString(clientConn, "GET /events HTTP/1.1\r\nHost: api.tunn.test\r\nAuthorization: Bearer "+token+"\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
			response, err := http.ReadResponse(bufio.NewReader(permissionByteReader{clientConn}), nil)
			if err != nil || response.StatusCode != 200 {
				t.Fatal("stream headers", response.StatusCode, err)
			}
			// Stop reading with one finite SSE record pending on a zero-buffer socket.
			start := time.Now()
			if outage {
				stalled.Store(true)
			} else {
				_, err = ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "unshare", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Email: "alice@example.com"})
				if err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
				t.Logf("authority change to downstream cutoff: %s", time.Since(start))
			case <-time.After(4 * time.Second):
				t.Fatal("downstream stalled reader exceeded cutoff")
			}
			if b.operations.active.Load() != 0 {
				t.Fatal("permission checks changed active-request accounting")
			}
		})
	}
}

func TestForwardedPermissionHTTP2SiblingSurvives(t *testing.T) {
	b, tunnel, ledger, _ := webSharingFixture(t)
	_, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: hello\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()
	a := securityProxy(b.storage)
	a.config.Insecure = true
	a.config.NodeSecret = "fixture-cluster"
	addr := strings.TrimPrefix(upstream.URL, "https://")
	authority := NewInternalServer(b.tunnelServer, addr, false)
	authority.proxy = b
	a.nodeClients = map[string]ipb.InternalServiceClient{"publisher": forwardPermissionPeer{server: authority}}
	var connections atomic.Int32
	edge := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_, _ = io.WriteString(w, "healthy")
			return
		}
		a.proxyToNode(w, r, addr, tunnel.TunnelID)
	}))
	edge.EnableHTTP2 = true
	edge.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			connections.Add(1)
		}
	}
	edge.StartTLS()
	defer edge.Close()
	client := edge.Client()
	client.Timeout = 6 * time.Second
	r, _ := http.NewRequest("GET", edge.URL+"/events", nil)
	r.Host = "api.tunn.test"
	r.Header.Set("Authorization", "Bearer "+relayJWT(t, b, "alice@example.com"))
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("stream admission", response.StatusCode)
	}
	if response.ProtoMajor != 2 {
		t.Fatal("HTTP/2 required")
	}
	line := make([]byte, len("data: hello\n\n"))
	if _, err = io.ReadFull(response.Body, line); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "unshare", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = response.Body.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked stream remained open")
	}
	t.Logf("authority commit to HTTP/2 stream cutoff: %s", time.Since(start))
	health, err := client.Get(edge.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer health.Body.Close()
	data, err := io.ReadAll(health.Body)
	if err != nil || string(data) != "healthy" || connections.Load() != 1 {
		t.Fatalf("sibling connection changed: connections=%d error=%v", connections.Load(), err)
	}
}
