package host

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/hostmode"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

// This test intentionally requires real loopback and Unix listeners. It must
// fail, rather than skip, when run in a sandbox that denies those listeners.
func TestLoopbackHostMode(t *testing.T) {
	t.Setenv("TUNN_CONFIG_DIR", t.TempDir())
	localHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Tunn-Authorization") != "" {
			t.Error("endpoint credential reached local target")
		}
		_, _ = io.WriteString(w, r.URL.RequestURI())
	}))
	defer localHTTP.Close()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	// A short repository-local path stays below macOS's Unix socket path limit.
	if err := os.MkdirAll(".scratch", 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(".scratch", "hm-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket, err := filepath.Abs(filepath.Join(dir, "u"))
	if err != nil {
		t.Fatal(err)
	}
	unix, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close() }()
	unixServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "socket-ok") })}
	go func() { _ = unixServer.Serve(unix) }()
	defer func() { _ = unixServer.Close() }()

	s := hostFixture(t)
	token := createTestJWT("owner@example.com", s.cfg.JWTSecret)
	account, err := s.hostAccount(token, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.accounts.UpdatePlan(account.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	pb.RegisterTunnelServiceServer(g, s)
	defer g.Stop()
	p := &ProxyServer{Domain: s.cfg.Domain, config: s.cfg, tunnelServer: s, grpcServer: g, storage: s.storage,
		usageBuffer: NewUsageBuffer(), quotaCache: NewQuotaCache(time.Minute), tunnelCache: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hosts", p.handleHosts)
	mux.HandleFunc("/", p.handleWebProxy)
	httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			p.handleWebProxy(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	relay := httptest.NewUnstartedServer(p.createHTTP2Router(httpHandler))
	relay.EnableHTTP2 = true
	relay.StartTLS()
	defer relay.Close()
	server := strings.TrimPrefix(relay.URL, "https://")
	c := &hostmode.Config{Version: 1, Machine: "gpu-box", Server: server, Domain: s.cfg.Domain, Insecure: true, Health: "127.0.0.1:0", Tunnels: []hostmode.Tunnel{
		{Name: "gpu-http", Kind: "http", Target: localHTTP.URL, Allow: []string{"owner@example.com"}},
		{Name: "gpu-mcp", Kind: "mcp", Target: localHTTP.URL + "/internal/mcp?fixed=1"},
		{Name: "gpu-ssh", Kind: "tcp", Target: echo.Addr().String()},
		{Name: "gpu-unix", Kind: "unix", As: "http", Target: socket},
	}}
	a := hostmode.API{Server: server, Token: token, Insecure: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listen := make(chan string, 1)
	done := make(chan error, 1)
	r := &hostmode.Runtime{Config: c, API: a, TunnelKey: s.cfg.WellKnownKey, OnListen: func(addr string) { listen <- addr }}
	go func() { done <- r.Run(ctx) }()
	var healthAddr string
	select {
	case healthAddr = <-listen:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not bind health")
	}
	waitHost := func(predicate func() bool) {
		t.Helper()
		deadline := time.NewTimer(8 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			if predicate() {
				return
			}
			select {
			case <-ticker.C:
			case <-deadline.C:
				t.Fatal("host state did not converge")
			case err := <-done:
				t.Fatalf("daemon stopped: %v", err)
			}
		}
	}
	waitHost(func() bool {
		machines, err := a.Hosts(ctx)
		if err != nil || len(machines) != 1 || len(machines[0].Tunnels) != 4 {
			return false
		}
		for _, e := range machines[0].Tunnels {
			if !e.Online {
				return false
			}
		}
		return true
	})
	httpClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	defer httpClient.CloseIdleConnections()
	request := func(name, path, credential string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, relay.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = name + "." + s.cfg.Domain
		req.Header.Set("Tunn-Authorization", "Bearer "+credential)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	httpToken, err := client.LoadEndpointToken("gpu-http")
	if err != nil {
		t.Fatal(err)
	}
	if status, body := request("gpu-http", "/hello?x=1", httpToken); status != 200 || body != "/hello?x=1" {
		t.Fatalf("HTTP = %d %q", status, body)
	}
	if status, _ := request("gpu-http", "/", "invalid"); status != 401 {
		t.Fatalf("unauthorized HTTP = %d", status)
	}
	mcpToken, err := client.LoadEndpointToken("gpu-mcp")
	if err != nil {
		t.Fatal(err)
	}
	if status, body := request("gpu-mcp", "/mcp?client=1", mcpToken); status != 200 || body != "/internal/mcp?fixed=1&client=1" {
		t.Fatalf("MCP mapping = %d %q", status, body)
	}
	unixToken, err := client.LoadEndpointToken("gpu-unix")
	if err != nil {
		t.Fatal(err)
	}
	if status, body := request("gpu-unix", "/", unixToken); status != 200 || body != "socket-ok" {
		t.Fatalf("Unix HTTP = %d %q", status, body)
	}
	tcpToken, err := client.LoadEndpointToken("gpu-ssh")
	if err != nil {
		t.Fatal(err)
	}
	connect, err := http.NewRequest(http.MethodConnect, relay.URL+common.TCPConnectPath, bytes.NewReader([]byte("ssh-bytes")))
	if err != nil {
		t.Fatal(err)
	}
	connect.Host = "gpu-ssh." + s.cfg.Domain
	connect.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
	connect.Header.Set("Tunn-Authorization", "Bearer "+tcpToken)
	response, err := httpClient.Do(connect)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "ssh-bytes" {
		t.Fatalf("TCP = %d %q %v", response.StatusCode, body, err)
	}
	healthResponse, err := http.Get("http://" + healthAddr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = healthResponse.Body.Close()
	if healthResponse.StatusCode != 200 {
		t.Fatal("daemon readiness never became healthy")
	}
	previous, _ := s.GetTunnel("gpu-http")
	relay.CloseClientConnections()
	waitHost(func() bool { next, found := s.GetTunnel("gpu-http"); return found && next != previous })
	if status, body := request("gpu-http", "/after-reconnect", httpToken); status != 200 || body != "/after-reconnect" {
		t.Fatalf("reconnect = %d %q", status, body)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon shutdown hung")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		machines, err := a.Hosts(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !machines[0].Online {
			for _, e := range machines[0].Tunnels {
				if e.LastSeen.IsZero() {
					t.Fatal("disconnect forgot last seen")
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("disconnected host still online")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if preserved, err := client.LoadEndpointToken("gpu-http"); err != nil || preserved != httpToken {
		t.Fatal("daemon lifecycle rotated saved token")
	}
}
