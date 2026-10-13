//go:build pythonsdk

package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These tests run a separate Python public-API consumer against the production
// relay handlers with disposable TLS, credentials and literal loopback sockets.
type pythonRelay struct {
	*TunnelServer
	mu    sync.Mutex
	names []string
	cut   chan struct{}
}
type pythonStream struct {
	pb.TunnelService_EstablishTunnelServer
	first *pb.TunnelMessage
	cut   <-chan struct{}
}

func (s *pythonStream) Recv() (*pb.TunnelMessage, error) {
	if s.first != nil {
		m := s.first
		s.first = nil
		return m, nil
	}
	type result struct {
		m   *pb.TunnelMessage
		err error
	}
	received := make(chan result, 1)
	go func() { m, err := s.TunnelService_EstablishTunnelServer.Recv(); received <- result{m, err} }()
	select {
	case r := <-received:
		return r.m, r.err
	case <-s.cut:
		return nil, status.Error(codes.Unavailable, "disposable connection cut")
	case <-s.Context().Done():
		return nil, s.Context().Err()
	}
}
func (s *pythonRelay) EstablishTunnel(stream pb.TunnelService_EstablishTunnelServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.names = append(s.names, first.GetRegisterClient().GetTunnelId())
	cut := s.cut
	if len(s.names) > 1 {
		cut = make(chan struct{})
	}
	s.mu.Unlock()
	return s.TunnelServer.EstablishTunnel(&pythonStream{TunnelService_EstablishTunnelServer: stream, first: first, cut: cut})
}
func (s *pythonRelay) registrations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.names...)
}

type pythonConsumer struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	output  *bufio.Reader
	done    chan error
	stderr  bytes.Buffer
}

func startPythonConsumer(t *testing.T, config map[string]any) *pythonConsumer {
	t.Helper()
	python := os.Getenv("TUNN_PYTHON")
	helper := os.Getenv("TUNN_PYTHON_HELPER")
	if python == "" || helper == "" {
		t.Fatal("run make test-python-contract with the Python ASGI extra installed")
	}
	script, err := filepath.Abs("../../sdk/python/tests/relay_consumer.py")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, python, script)
	p := &pythonConsumer{command: command, done: make(chan error, 1)}
	p.stdin, err = command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.output = bufio.NewReader(stdout)
	command.Stderr = &p.stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- command.Wait() }()
	t.Cleanup(func() {
		_ = p.stdin.Close()
		select {
		case err := <-p.done:
			if err != nil {
				t.Errorf("Python consumer exit: %v; %s", err, p.stderr.String())
			}
		case <-time.After(6 * time.Second):
			_ = command.Process.Kill()
			<-p.done
			t.Error("Python consumer failed to join")
		}
	})
	p.send(t, config)
	return p
}
func (p *pythonConsumer) send(t *testing.T, value any) {
	t.Helper()
	if err := json.NewEncoder(p.stdin).Encode(value); err != nil {
		t.Fatal(err)
	}
}
func (p *pythonConsumer) read(t *testing.T) map[string]any {
	t.Helper()
	type result struct {
		data []byte
		err  error
	}
	resultCh := make(chan result, 1)
	go func() { line, err := p.output.ReadBytes('\n'); resultCh <- result{line, err} }()
	select {
	case r := <-resultCh:
		if r.err != nil {
			t.Fatalf("Python consumer response: %v", r.err)
		}
		var data map[string]any
		if err := json.Unmarshal(r.data, &data); err != nil {
			t.Fatalf("invalid consumer output: %v", err)
		}
		return data
	case <-time.After(8 * time.Second):
		t.Fatal("Python consumer response deadline")
		return nil
	}
}
func pythonStack(t *testing.T, mode string, public bool, auth string) (*webSocketStack, *pythonRelay, *pythonConsumer, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{ClientSecret: "python-publisher-fixture", Domain: "tunn.test", JWTSecret: "python-cookie-fixture", NodeSecret: "python-node-fixture"}
	server := &pythonRelay{TunnelServer: NewTunnelServer(cfg, nil, nil, nil), cut: make(chan struct{})}
	gs := grpc.NewServer()
	pb.RegisterTunnelServiceServer(gs, server)
	proxy := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: server.TunnelServer, grpcServer: gs,
		storage: storage.NewProxyStorage(), quotaCache: NewQuotaCache(time.Minute)}
	relay := httptest.NewUnstartedServer(proxy.createHTTP2Router(http.HandlerFunc(proxy.handleWebProxy)))
	relay.EnableHTTP2 = true
	relay.StartTLS()
	t.Cleanup(func() { gs.Stop(); relay.Close() })
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: relay.Certificate().Raw}))
	credentials := map[string]string{"auth_token": auth, "tunnel_key": "", "endpoint_token": sdkEndpointToken}
	emails := []string{"alice@example.com"}
	if public {
		credentials["endpoint_token"] = ""
		emails = nil
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Set-Cookie", "one=one; Path=/")
		w.Header().Add("Set-Cookie", "two=two; Path=/")
		_ = json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path, "query": r.URL.RawQuery, "body": string(body),
			"auth": r.Header.Get("Authorization"), "tunnAuth": r.Header.Get("Tunn-Authorization"), "host": r.Host, "proto": r.Header.Get("X-Forwarded-Proto")})
	}))
	t.Cleanup(origin.Close)
	input := map[string]any{"mode": mode, "server_addr": relay.Listener.Addr().String(), "ca_pem": ca,
		"credentials": credentials, "public": public, "allowed_emails": emails}
	if strings.HasSuffix(mode, "origin") {
		input["origin"] = origin.URL
	}
	consumer := startPythonConsumer(t, input)
	stack := &webSocketStack{relay: relay, proxy: proxy}
	return stack, server, consumer, origin
}
func pythonRequest(t *testing.T, stack *webSocketStack, path, body string, headers http.Header) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, stack.relay.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "websocket-fixture.tunn.test"
	request.Header = headers.Clone()
	client := &http.Client{Transport: stack.relay.Client().Transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func pythonClose(t *testing.T, consumer *pythonConsumer, op string) map[string]any {
	t.Helper()
	consumer.send(t, map[string]string{"op": op})
	closed := consumer.read(t)
	if closed["phase"] != "closed" {
		t.Fatalf("closure: %v", closed)
	}
	events := closed["events"].([]any)
	count := 0
	for _, e := range events {
		if e == "closed" {
			count++
		}
	}
	if count != 1 || events[len(events)-1] != "closed" {
		t.Fatalf("terminal events: %v", events)
	}
	return closed
}
func TestPythonSDKHTTPAuthAndHandlerParity(t *testing.T) {
	for _, mode := range []string{"sync-origin", "async-origin", "sync-handler", "async-handler", "wsgi"} {
		t.Run(mode, func(t *testing.T) {
			stack, server, consumer, origin := pythonStack(t, mode, false, "python-publisher-fixture")
			ready := consumer.read(t)
			if ready["phase"] != "ready" || ready["url"] != "https://websocket-fixture.tunn.test" {
				t.Fatalf("ready: %v", ready)
			}
			tunnel, ok := server.GetTunnel("websocket-fixture")
			if !ok {
				t.Fatal("no registration")
			}
			stack.tunnel = tunnel
			digest := sha256.Sum256([]byte(sdkEndpointToken))
			if tunnel.TargetURL != "http" || !bytes.Equal(tunnel.accessTokenDigest(), digest[:]) || !tunnel.Supports(common.CapabilityHTTPStreamV1) ||
				!reflect.DeepEqual(tunnel.AllowedEmails, []string{"alice@example.com"}) {
				t.Fatalf("registration options differ")
			}
			denied := pythonRequest(t, stack, "/http", "", nil)
			_ = denied.Body.Close()
			if denied.StatusCode != http.StatusFound {
				t.Fatalf("anonymous access: %d", denied.StatusCode)
			}
			response := pythonRequest(t, stack, "/http?query=one", "payload", http.Header{"Tunn-Authorization": {"Bearer " + sdkEndpointToken}, "Authorization": {"Bearer application-fixture"}})
			defer response.Body.Close()
			var result map[string]string
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"path": "/http", "query": "query=one", "body": "payload", "auth": "Bearer application-fixture", "tunnAuth": "", "host": "websocket-fixture.tunn.test", "proto": "https"}
			if response.StatusCode != 200 || !reflect.DeepEqual(result, want) || len(response.Cookies()) != 2 {
				t.Fatalf("HTTP parity: %d %v %v", response.StatusCode, result, response.Header)
			}
			allowed := pythonRequest(t, stack, "/http", "", http.Header{"Cookie": {stack.cookie(t, "alice@example.com")}})
			_ = allowed.Body.Close()
			if allowed.StatusCode != 200 {
				t.Fatalf("sharing access: %d", allowed.StatusCode)
			}
			if closed := pythonClose(t, consumer, "close"); closed["code"] != "" {
				t.Fatalf("close: %v", closed)
			}
			direct, err := origin.Client().Get(origin.URL + "/http")
			if err != nil {
				t.Fatal("Close stopped caller origin")
			}
			_ = direct.Body.Close()
		})
	}
}
func TestPythonSDKPublisherAuthAndPublicChoice(t *testing.T) {
	t.Run("publisher-rejected", func(t *testing.T) {
		_, _, consumer, _ := pythonStack(t, "async-handler", false, "wrong-fixture-auth")
		result := consumer.read(t)
		if result["phase"] != "error" || result["code"] != "registration_rejected" {
			t.Fatalf("auth failure: %v", result)
		}
	})
	t.Run("explicit-public", func(t *testing.T) {
		stack, server, consumer, _ := pythonStack(t, "sync-handler", true, "python-publisher-fixture")
		if result := consumer.read(t); result["phase"] != "ready" {
			t.Fatalf("public ready: %v", result)
		}
		tunnel, _ := server.GetTunnel("websocket-fixture")
		if tunnel.ExposureMode != "public" || len(tunnel.AllowedEmails) != 0 || len(tunnel.accessTokenDigest()) != 0 {
			t.Fatal("public flag did not reach relay")
		}
		response := pythonRequest(t, stack, "/http", "", nil)
		_ = response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("explicit public access: %d", response.StatusCode)
		}
		pythonClose(t, consumer, "close")
	})
}
func TestPythonSDKReconnectStreamAndWebSocketCancellation(t *testing.T) {
	stack, server, consumer, _ := pythonStack(t, "async-handler", false, "python-publisher-fixture")
	ready := consumer.read(t)
	if ready["phase"] != "ready" {
		t.Fatalf("ready: %v", ready)
	}
	close(server.cut)
	deadline := time.Now().Add(3 * time.Second)
	for len(server.registrations()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	names := server.registrations()
	if len(names) != 2 || names[0] != names[1] {
		t.Fatalf("reconnect identity: %v", names)
	}
	for {
		consumer.send(t, map[string]string{"op": "status"})
		state := consumer.read(t)
		if state["state"] == "ready" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reconnect did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	headers := http.Header{"Tunn-Authorization": {"Bearer " + sdkEndpointToken}}
	conn, reader := mustWebSocket(t, stack, "/echo", headers)
	defer conn.Close()
	for _, opcode := range []byte{1, 2} {
		payload := []byte("Python WebSocket fixture")
		_, _ = conn.Write(fixtureFrame(opcode, true, true, payload))
		expectWireFrame(t, reader, opcode, payload)
	}
	response := pythonRequest(t, stack, "/stream", "", headers)
	defer response.Body.Close()
	prefix := make([]byte, len("data: prefix\n\n"))
	if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "data: prefix\n\n" {
		t.Fatalf("streaming prefix: %q %v", prefix, err)
	}
	closed := pythonClose(t, consumer, "cancel")
	if closed["code"] != "cancelled" || closed["cancelled_handlers"].(float64) != 1 {
		t.Fatalf("cancellation: %v", closed)
	}
	events := closed["events"].([]any)
	if !strings.Contains(fmt.Sprint(events), "reconnecting") {
		t.Fatalf("missing reconnect event: %v", events)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := fixtureReadFrame(reader, false); err == nil {
		t.Fatal("WebSocket stayed open after cancel")
	}
	if _, err := response.Body.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream stayed open after cancel")
	}
}
func TestPythonSDKMCPQuickstart(t *testing.T) {
	stack, _, consumer, _ := pythonStack(t, "mcp", false, "python-publisher-fixture")
	if ready := consumer.read(t); ready["phase"] != "ready" {
		t.Fatalf("MCP ready: %v", ready)
	}
	headers := http.Header{"Tunn-Authorization": {"Bearer " + sdkEndpointToken}, "Content-Type": {"application/json"}, "Accept": {"application/json, text/event-stream"}}
	request := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`
	initialized := pythonRequest(t, stack, "/mcp", request, headers)
	data, _ := io.ReadAll(initialized.Body)
	_ = initialized.Body.Close()
	if initialized.StatusCode != 200 || !bytes.Contains(data, []byte("protocolVersion")) {
		t.Fatalf("MCP initialization: %d %s", initialized.StatusCode, data)
	}
	headers.Set("MCP-Protocol-Version", "2025-03-26")
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":3}}}`
	response := pythonRequest(t, stack, "/mcp", call, headers)
	data, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || !bytes.Contains(data, []byte(`"text":"5"`)) {
		t.Fatalf("MCP tool call: %d %s", response.StatusCode, data)
	}
	deniedHeaders := headers.Clone()
	deniedHeaders.Set("Origin", "https://unapproved.test")
	denied := pythonRequest(t, stack, "/mcp", call, deniedHeaders)
	_ = denied.Body.Close()
	if denied.StatusCode != 403 {
		t.Fatalf("MCP Origin guard: %d", denied.StatusCode)
	}
	pythonClose(t, consumer, "close")
}

func TestPythonSDKPrivateDefaultOwnerOnly(t *testing.T) {
	fixture := newMCPOAuthFixture(t)
	proxy := fixture.p
	proxy.tunnelServer.SetSharingBackend(proxy.meter.(metering.SharingBackend))
	gs := grpc.NewServer()
	pb.RegisterTunnelServiceServer(gs, proxy.tunnelServer)
	proxy.grpcServer = gs
	relay := httptest.NewUnstartedServer(proxy.createHTTP2Router(proxy.createHandler()))
	relay.EnableHTTP2 = true
	relay.StartTLS()
	t.Cleanup(func() { gs.Stop(); relay.Close() })
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: relay.Certificate().Raw}))
	consumer := startPythonConsumer(t, map[string]any{"mode": "async-handler", "server_addr": relay.Listener.Addr().String(), "ca_pem": ca,
		"credentials": map[string]string{"auth_token": relayJWT(t, proxy, "owner@example.com"), "tunnel_key": proxy.config.WellKnownKey}})
	if ready := consumer.read(t); ready["phase"] != "ready" {
		t.Fatalf("private default ready: %v", ready)
	}
	tunnel, ok := proxy.tunnelServer.GetTunnel("websocket-fixture")
	if !ok || tunnel.ExposureMode != "private" || tunnel.ResourceID == "" || tunnel.AccountID == "" {
		t.Fatal("private ownership did not reach relay")
	}
	stack := &webSocketStack{relay: relay, proxy: proxy, tunnel: tunnel}
	for _, entry := range []struct {
		email string
		code  int
	}{{"", 302}, {"bob@example.com", 403}, {"owner@example.com", 200}} {
		headers := http.Header{}
		if entry.email != "" {
			headers.Set("Cookie", securityCookie(t, proxy, entry.email).String())
		}
		response := pythonRequest(t, stack, "/http", "", headers)
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != entry.code {
			t.Fatalf("private admission %q: %d", entry.email, response.StatusCode)
		}
	}
	pythonClose(t, consumer, "close")
}
