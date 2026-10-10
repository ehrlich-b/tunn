package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func opsFreeTCP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func opsHeadlessProxy(t *testing.T) *ProxyServer {
	t.Helper()
	db, err := store.OpenLocal(filepath.Join(t.TempDir(), "tunn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{Domain: "tunn.test", JWTSecret: "fixture-signing-secret", ClientSecret: "fixture-publisher-secret", InternalGRPCPort: "invalid-address"}
	local := storage.NewLocalStorage(db)
	tunnel := NewTunnelServer(cfg, nil, nil, local)
	gs, internal := grpc.NewServer(), grpc.NewServer()
	pb.RegisterTunnelServiceServer(gs, tunnel)
	return &ProxyServer{Domain: cfg.Domain, config: cfg, storage: local, isLoginNode: true, tunnelServer: tunnel, grpcServer: gs, internalGRPCServer: internal, HTTP2Addr: "invalid-address", HTTP3Addr: "invalid-address", tlsConfig: &tls.Config{}}
}

func TestOpsRelayOfflineReadinessStates(t *testing.T) {
	p := opsHeadlessProxy(t)
	p.requiredListeners.Store(listenerHTTP2 | listenerHTTP3 | listenerInternal)
	for _, state := range []uint32{0, listenerHTTP2, listenerHTTP2 | listenerHTTP3, listenerHTTP2 | listenerHTTP3 | listenerInternal} {
		p.listenerState.Store(state)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.test/readyz", nil))
		want := 503
		if state == p.requiredListeners.Load() {
			want = 200
		}
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("readiness state %d: %d", state, w.Code)
		}
	}
	p.stopping.Store(true)
	if p.ready(context.Background()) {
		t.Fatal("stopping relay reported ready")
	}
	p.stopping.Store(false)
	p.storage = storage.NewProxyStorage()
	if p.ready(context.Background()) {
		t.Fatal("unavailable storage reported ready")
	}
	for _, path := range []string{"/health", "/healthz"} {
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.test"+path, nil))
		if w.Code != 200 || w.Body.String() != "ok" {
			t.Fatal("dependency outage broke liveness")
		}
		w = httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, httptest.NewRequest("HEAD", "https://tunn.test"+path, nil))
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal("HEAD health emitted a body")
		}
	}
}

func TestOpsRelayOfflineStartupFailureJoinsWorkers(t *testing.T) {
	p := opsHeadlessProxy(t)
	_, done := opsStart(t, p)
	if err := opsWaitStopped(t, done); err == nil {
		t.Fatal("invalid listeners started successfully")
	}
	if p.listenerState.Load() != 0 || !p.stopping.Load() {
		t.Fatal("failed startup retained readiness")
	}
}
func opsFreeUDP(t *testing.T) string {
	t.Helper()
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().String()
	_ = l.Close()
	return addr
}

func opsProxy(t *testing.T) (*ProxyServer, *http.Client, *sql.DB) {
	t.Helper()
	root := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tunn.test"}, DNSNames: []string{"tunn.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Environment: config.EnvDev, Domain: "tunn.test", CertFile: certPath, KeyFile: keyPath, HTTP2Addr: opsFreeTCP(t), HTTP3Addr: opsFreeUDP(t), InternalGRPCPort: opsFreeTCP(t), PublicAddr: "tunn.test:443", ClientSecret: "fixture-publisher-secret", JWTSecret: "fixture-signing-secret", NodeSecret: "fixture-node-secret"}
	p, err := NewProxyServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenLocal(filepath.Join(root, "tunn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	p.isLoginNode = true
	p.storage = storage.NewLocalStorage(db)
	p.tunnelServer.storage = p.storage
	pool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}
	t.Cleanup(transport.CloseIdleConnections)
	return p, &http.Client{Transport: transport, Timeout: time.Second}, db
}

func opsStart(t *testing.T, p *ProxyServer) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	t.Cleanup(cancel)
	return cancel, done
}

func opsWaitHealth(t *testing.T, p *ProxyServer, client *http.Client, path string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequest(http.MethodGet, "https://"+p.HTTP2Addr+path, nil)
		request.Host = p.Domain
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == want {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never returned %d", path, want)
}

func opsWaitStopped(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("relay failed to stop")
		return nil
	}
}

func opsAssertReleased(t *testing.T, p *ProxyServer) {
	t.Helper()
	for _, addr := range []string{p.HTTP2Addr, p.config.InternalGRPCPort} {
		l, err := net.Listen("tcp4", addr)
		if err != nil {
			t.Errorf("TCP listener retained after Run returned: %v", err)
		} else {
			_ = l.Close()
		}
	}
	l, err := net.ListenPacket("udp", p.HTTP3Addr)
	if err != nil {
		t.Errorf("UDP listener retained after Run returned: %v", err)
	} else {
		_ = l.Close()
	}
}

func TestOpsLoopbackReadinessLifecycleAndDependency(t *testing.T) {
	p, client, db := opsProxy(t)
	handler := p.createHandler()
	check := func(path string, want int) {
		r := httptest.NewRequest(http.MethodGet, "https://tunn.test"+path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s returned %d: %s", path, w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("health result may be cached")
		}
	}
	check("/health", 200)
	check("/healthz", 200)
	check("/readyz", 503)
	cancel, done := opsStart(t, p)
	opsWaitHealth(t, p, client, "/readyz", 200)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	check("/readyz", 503)
	check("/healthz", 200)
	cancel()
	if err := opsWaitStopped(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	check("/readyz", 503)
	opsAssertReleased(t, p)
}

func TestOpsRelayHealthMethodsAndOrigins(t *testing.T) {
	p := opsHeadlessProxy(t)
	for _, path := range []string{"/health", "/healthz", "/readyz"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			r := httptest.NewRequest(method, "https://tunn.test"+path, nil)
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, r)
			if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
				t.Fatalf("health method %s %s: %d", method, path, w.Code)
			}
		}
		r := httptest.NewRequest(http.MethodGet, "https://offline.tunn.test"+path, nil)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code == 200 || strings.TrimSpace(w.Body.String()) == "ok" {
			t.Fatal("platform health masked offline publisher")
		}
	}
}

func TestOpsLoopbackStartupFailureReleasesSiblingListeners(t *testing.T) {
	for _, listener := range []string{"http2", "http3", "internal"} {
		t.Run(listener, func(t *testing.T) {
			p, _, _ := opsProxy(t)
			switch listener {
			case "http2":
				p.HTTP2Addr = "not-an-address"
			case "http3":
				p.HTTP3Addr = "not-an-address"
			case "internal":
				p.config.InternalGRPCPort = "not-an-address"
			}
			_, done := opsStart(t, p)
			if err := opsWaitStopped(t, done); err == nil {
				t.Fatal("startup failure returned success")
			}
			if listener == "http2" {
				p.HTTP2Addr = opsFreeTCP(t)
			}
			if listener == "http3" {
				p.HTTP3Addr = opsFreeUDP(t)
			}
			if listener == "internal" {
				p.config.InternalGRPCPort = opsFreeTCP(t)
			}
			opsAssertReleased(t, p)
		})
	}
}

func TestOpsLoopbackShutdownWithLivePublisherAndRestart(t *testing.T) {
	p, client, _ := opsProxy(t)
	cancel, done := opsStart(t, p)
	opsWaitHealth(t, p, client, "/health", 200)
	conn, err := grpc.NewClient("passthrough:///"+p.HTTP2Addr, grpc.WithTransportCredentials(credentials.NewTLS(client.Transport.(*http.Transport).TLSClientConfig)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	streamCtx, stopStream := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopStream()
	stream, err := pb.NewTunnelServiceClient(conn).EstablishTunnel(streamCtx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "restart-fixture", TunnelKey: p.config.ClientSecret}}}); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil || !response.GetRegisterResponse().GetSuccess() {
		t.Fatalf("live publisher registration: %v %v", response, err)
	}
	cancel()
	if err := opsWaitStopped(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("publisher stream survived stopped relay")
	}
	if _, exists := p.tunnelServer.GetTunnel("restart-fixture"); exists {
		t.Fatal("stopped relay retained live registration")
	}
	opsAssertReleased(t, p)
	// Restart a fresh relay on the same ports, as a replacement process does.
	next, nextClient, _ := opsProxy(t)
	next.HTTP2Addr, next.HTTP3Addr, next.config.InternalGRPCPort = p.HTTP2Addr, p.HTTP3Addr, p.config.InternalGRPCPort
	nextCancel, nextDone := opsStart(t, next)
	opsWaitHealth(t, next, nextClient, "/readyz", 200)
	nextCancel()
	if err := opsWaitStopped(t, nextDone); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
