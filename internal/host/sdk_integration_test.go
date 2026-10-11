package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/testutil/httpconformance"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	tunn "github.com/ehrlich-b/tunn/sdk"
	"google.golang.org/grpc"
)

const sdkEndpointToken = "tunn_ep_sdk-contract-credential-sentinel"

type sdkContractStack struct {
	*webSocketStack
	server         *TunnelServer
	tunnelSDK      *tunn.Tunnel
	closePublisher func() error
	local          *httptest.Server
}

// Deliberately binds literal loopback: this is the SDK acceptance gate, not
// the memory fixture fallback. It uses the established WebSocket wire fixture.
func startSDKContractStack(t *testing.T, mode string, responseOptions ...sdkResponseContract) *sdkContractStack {
	t.Helper()
	fixture := &webSocketFixture{closes: make(chan []byte, 16)}
	cfg := &config.Config{ClientSecret: "sdk-publisher-auth-fixture", Domain: "tunn.test", JWTSecret: "sdk-cookie-signing-fixture", NodeSecret: "sdk-node-fixture"}
	server := NewTunnelServer(cfg, nil, nil, nil)
	var relayImpl pb.TunnelServiceServer = server
	if len(responseOptions) == 1 && responseOptions[0].Mode == httpconformance.Buffered {
		relayImpl = &sdkBufferedRelay{TunnelServer: server}
	}
	gs := grpc.NewServer()
	pb.RegisterTunnelServiceServer(gs, relayImpl)
	proxy := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: server, grpcServer: gs, storage: storage.NewProxyStorage(), quotaCache: NewQuotaCache(time.Minute)}
	relay := httptest.NewUnstartedServer(proxy.createHTTP2Router(http.HandlerFunc(proxy.handleWebProxy)))
	relay.EnableHTTP2 = true
	relay.StartTLS()
	t.Cleanup(func() { gs.Stop(); relay.Close() })
	pool := x509.NewCertPool()
	pool.AddCert(relay.Certificate())
	tlsConfig := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stack := &sdkContractStack{webSocketStack: &webSocketStack{relay: relay, proxy: proxy, fixture: fixture, cancel: cancel}, server: server}
	o := tunn.Options{Name: "websocket-fixture", ServerAddr: relay.Listener.Addr().String(), Credentials: tunn.Credentials{AuthToken: cfg.ClientSecret, EndpointToken: sdkEndpointToken}, AllowedEmails: []string{"alice@example.com"}, TLSConfig: tlsConfig, Reconnect: &tunn.ReconnectPolicy{MaxAttempts: 3, InitialDelay: 5 * time.Millisecond, MaxDelay: 20 * time.Millisecond}, ConnectTimeout: time.Second}
	var handler http.Handler = fixture
	if len(responseOptions) > 0 {
		handler = responseOptions[0].Handler
	}
	if mode == "handler" {
		var err error
		stack.tunnelSDK, err = tunn.PublishHandler(ctx, handler, o)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		stack.local = httptest.NewServer(handler)
		t.Cleanup(stack.local.Close)
		if mode == "origin" {
			o.Origin = stack.local.URL
			var err error
			stack.tunnelSDK, err = tunn.Publish(ctx, o)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			digest := sha256.Sum256([]byte(sdkEndpointToken))
			core := &client.ServeClient{TunnelID: o.Name, TargetURL: stack.local.URL, ServerAddr: o.ServerAddr, AuthToken: o.Credentials.AuthToken, AccessTokenSHA256: digest[:], AllowedEmails: o.AllowedEmails, RelayTLSConfig: tlsConfig, Quiet: true, InitialDelay: 5 * time.Millisecond, MaxReconnectDelay: 20 * time.Millisecond, WebSocket: &common.WebSocketOptions{IdleTimeout: time.Minute, MaxMessageSize: 8 << 20}}
			done := make(chan error, 1)
			go func() { done <- core.Run(ctx) }()
			stack.closePublisher = func() error {
				cancel()
				select {
				case err := <-done:
					if errors.Is(err, context.Canceled) {
						return nil
					}
					return err
				case <-time.After(3 * time.Second):
					return errors.New("CLI core did not stop")
				}
			}
		}
	}
	if stack.tunnelSDK != nil {
		readyCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		if _, err := stack.tunnelSDK.WaitReady(readyCtx); err != nil {
			t.Fatal(err)
		}
		stack.closePublisher = stack.tunnelSDK.Close
	}
	closePublisher := stack.closePublisher
	closed := false
	stack.closePublisher = func() error {
		if closed {
			return nil
		}
		closed = true
		return closePublisher()
	}
	t.Cleanup(func() {
		if err := stack.closePublisher(); err != nil {
			t.Error(err)
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if tunnel, ok := server.GetTunnel(o.Name); ok {
			stack.tunnel = tunnel
			return stack
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("publisher did not register")
	return nil
}

func sdkHTTPRequest(t *testing.T, stack *sdkContractStack, headers http.Header) (int, map[string]string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, stack.relay.URL+"/http", nil)
	req.Host = "websocket-fixture.tunn.test"
	req.Header = headers.Clone()
	consumer := &http.Client{Transport: stack.relay.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := consumer.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var result map[string]string
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, result
}

func TestSDKCLIHTTPAndWebSocketContract(t *testing.T) {
	var reference map[string]string
	for _, mode := range []string{"cli", "origin", "handler"} {
		t.Run(mode, func(t *testing.T) {
			s := startSDKContractStack(t, mode)
			if s.tunnel.TargetURL != "http" || s.tunnel.CreatorEmail != "client@local" || !s.tunnel.Supports(common.CapabilityHTTPStreamV1) || !s.tunnel.Supports(common.CapabilityWebSocketV1) {
				t.Fatalf("registration semantics: %+v", s.tunnel)
			}
			if code, _ := sdkHTTPRequest(t, s, nil); code != http.StatusFound {
				t.Fatalf("anonymous browser auth redirect: %d", code)
			}
			headers := http.Header{"Tunn-Authorization": {"Bearer " + sdkEndpointToken}, "Authorization": {"Bearer application-fixture"}, "Origin": {"https://browser.example"}}
			code, result := sdkHTTPRequest(t, s, headers)
			if code != http.StatusOK || result["auth"] != "Bearer application-fixture" || result["tunnAuth"] != "" || result["proto"] != "https" || result["host"] != "websocket-fixture.tunn.test" {
				t.Fatalf("HTTP credential/header fidelity: %d %v", code, result)
			}
			delete(result, "for") // actual ephemeral peer address differs across fixtures
			if reference == nil {
				reference = result
			} else if !reflect.DeepEqual(reference, result) {
				t.Fatalf("CLI/SDK HTTP differs: %v / %v", reference, result)
			}
			cookie := http.Header{"Cookie": {s.cookie(t, "alice@example.com")}}
			if code, _ := sdkHTTPRequest(t, s, cookie); code != http.StatusOK {
				t.Fatalf("shared account cookie: %d", code)
			}
			bad := http.Header{"Tunn-Authorization": {"Bearer tunn_ep_wrong"}}
			conn, _, resp, err := s.dial("/echo", bad, nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			if resp.StatusCode != 401 {
				t.Fatalf("WebSocket auth denial: %d", resp.StatusCode)
			}
			conn, reader := mustWebSocket(t, s.webSocketStack, "/headers?request=one", headers)
			frame, err := fixtureReadFrame(reader, false)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(frame.payload, []byte(sdkEndpointToken)) || !bytes.Contains(frame.payload, []byte("application-fixture")) || !bytes.Contains(frame.payload, []byte("/headers?request=one")) {
				t.Fatalf("WebSocket header fidelity: %s", frame.payload)
			}
			for _, opcode := range []byte{1, 2} {
				payload := []byte("SDK transport fixture")
				_, _ = conn.Write(fixtureFrame(opcode, true, true, payload))
				expectWireFrame(t, reader, opcode, payload)
			}
			_, _ = conn.Write(fixtureFrame(9, true, true, []byte("ping")))
			expectWireFrame(t, reader, 10, []byte("ping"))
			_, _ = conn.Write(fixtureFrame(8, true, true, []byte{3, 232}))
			expectWireFrame(t, reader, 8, []byte{3, 232})
			_ = conn.Close()
			waitWebSocketsClosed(t, s.webSocketStack)
			if err := s.closePublisher(); err != nil {
				t.Fatal(err)
			}
			if s.local != nil {
				resp, err := s.local.Client().Get(s.local.URL + "/http")
				if err != nil {
					t.Fatalf("Close shut down caller origin: %v", err)
				}
				_ = resp.Body.Close()
			}
		})
	}
}

func TestSDKActiveWebSocketClose(t *testing.T) {
	s := startSDKContractStack(t, "handler")
	conn, reader := mustWebSocket(t, s.webSocketStack, "/echo", http.Header{"Tunn-Authorization": {"Bearer " + sdkEndpointToken}})
	_, _ = conn.Write(fixtureFrame(1, true, true, []byte("before close")))
	expectWireFrame(t, reader, 1, []byte("before close"))
	if err := s.tunnelSDK.Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.Copy(io.Discard, reader); err != nil {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			t.Fatal("public WebSocket remained open after Close")
		}
	}
	waitWebSocketsClosed(t, s.webSocketStack)
}

// sdkBufferedRelay changes only the synthetic registration before publication.
type sdkBufferedRelay struct{ *TunnelServer }

func (s *sdkBufferedRelay) EstablishTunnel(stream pb.TunnelService_EstablishTunnelServer) error {
	return s.TunnelServer.EstablishTunnel(responseBufferedRegistration{stream})
}

type sdkResponseContract struct {
	Handler http.Handler
	Mode    httpconformance.Mode
}
