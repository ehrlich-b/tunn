package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/ehrlich-b/tunn/internal/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/ehrlich-b/tunn/internal/trafficpolicy"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func policyRelay(t *testing.T, streaming bool) (*ProxyServer, *TunnelConnection, *metering.Store, *meteringFixtureStream) {
	t.Helper()
	p, tunnel, ledger, stream := meteringRelay(t, streaming, "origin")
	out, err := ledger.Sharing(context.Background(), &meterpb.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Mode: "private"})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.ResourceID = out.Resources[0].Id
	return p, tunnel, ledger, stream
}
func relayPolicy(t *testing.T, p *ProxyServer, tunnel *TunnelConnection, policy string) {
	t.Helper()
	out, err := p.meter.(metering.PolicyBackend).EndpointPolicy(context.Background(), &meterpb.EndpointPolicyRequest{Operation: "set", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, PolicyJson: []byte(policy)})
	if err != nil || out == nil {
		t.Fatalf("set policy: %v", err)
	}
}

func TestPolicyRelayAfterAuthBeforeBufferedAndStreamingOrigin(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{false: "buffered", true: "streamed"}[streaming], func(t *testing.T) {
			p, tunnel, _, stream := policyRelay(t, streaming)
			relayPolicy(t, p, tunnel, `{"headers":{"remove":["X-Remove"],"rewrite":[{"name":"X-Rewrite","value":"owner"}],"add":[{"name":"X-Add","value":"extra"}]},"rate_limits":{"per_ip":{"requests_per_minute":1,"burst":1},"per_account":{"requests_per_minute":1,"burst":1}}}`)
			r := relayRequest("invalid", "")
			r.RemoteAddr = "192.0.2.1:1234"
			w := httptest.NewRecorder()
			p.handleWebProxy(w, r)
			if w.Code != 401 {
				t.Fatalf("auth=%d %s", w.Code, w.Body)
			}
			stream.mu.Lock()
			count := len(stream.sentMsgs)
			stream.mu.Unlock()
			if count != 0 {
				t.Fatal("unauthenticated origin dispatch")
			}
			r = relayRequest(relayJWT(t, p, "owner@example.com"), "body")
			r.RemoteAddr = "192.0.2.1:1234"
			r.Header.Set("Authorization", "Bearer origin-credential")
			r.Header.Set("X-Remove", "gone")
			r.Header.Set("X-Rewrite", "visitor")
			r.Header.Set("X-Add", "first")
			w = httptest.NewRecorder()
			p.handleWebProxy(w, r)
			if w.Code != 200 || w.Body.String() != "origin" {
				t.Fatalf("forward=%d %s", w.Code, w.Body)
			}
			stream.mu.Lock()
			var headers map[string]string
			for _, msg := range stream.sentMsgs {
				if req := msg.GetHttpRequest(); req != nil {
					headers = req.Headers
				}
				if open := msg.GetConnectionOpen(); open != nil {
					headers = open.GetHttpRequest().GetHeaders()
				}
			}
			count = len(stream.sentMsgs)
			stream.mu.Unlock()
			if headers["X-Remove"] != "" || headers["X-Rewrite"] != "owner" || headers["X-Add"] != "first, extra" || headers["Tunn-Authorization"] != "" || headers["Authorization"] != "Bearer origin-credential" || headers["X-Forwarded-For"] != "192.0.2.1" {
				t.Fatalf("origin headers=%v", headers)
			}
			r = relayRequest(relayJWT(t, p, "owner@example.com"), "")
			r.RemoteAddr = "192.0.2.1:9999"
			w = httptest.NewRecorder()
			p.handleWebProxy(w, r)
			if w.Code != 429 || w.Header().Get("Retry-After") == "" {
				t.Fatalf("rate=%d %v", w.Code, w.Header())
			}
			stream.mu.Lock()
			defer stream.mu.Unlock()
			if len(stream.sentMsgs) != count {
				t.Fatal("rate-rejected request reached origin")
			}
		})
	}
}

func TestPolicyRelayIgnoresSpoofedPeerAndAcceptsSignedClusterHop(t *testing.T) {
	p, tunnel, _, _ := policyRelay(t, false)
	p.config.NodeSecret = "policy-cluster-fixture"
	relayPolicy(t, p, tunnel, `{"rate_limits":{"per_ip":{"requests_per_minute":1,"burst":1}}}`)
	request := func(peer, spoof, signature string) int {
		r := relayRequest(relayJWT(t, p, "owner@example.com"), "")
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", spoof)
		r.Header.Set("X-Real-IP", spoof)
		r.Header.Set("Forwarded", "for="+spoof)
		r.Header.Set(relayForwardedFor, spoof)
		r.Header.Set(relayForwardedProto, "https")
		r.Header.Set(relayForwardedSignature, signature)
		w := httptest.NewRecorder()
		p.handleWebProxy(w, r)
		return w.Code
	}
	if request("192.0.2.1:1234", "198.51.100.1", "forged") != 200 || request("192.0.2.1:1235", "198.51.100.2", "forged") != 429 {
		t.Fatal("spoofed forwarding header bypassed IP bucket")
	}
	signed := p.forwardingSignature("api.tunn.test", "198.51.100.3", "https")
	if request("192.0.2.1:1236", "198.51.100.3", signed) != 200 || request("192.0.2.2:1237", "198.51.100.3", signed) != 429 {
		t.Fatal("verified relay peer not preserved")
	}
}

type unavailablePolicyBackend struct {
	metering.Backend
	metering.SharingBackend
}

func (b *unavailablePolicyBackend) EndpointPolicy(context.Context, *meterpb.EndpointPolicyRequest) (*meterpb.EndpointPolicyResponse, error) {
	return nil, errors.New("fixture outage")
}

func TestPolicyRelayFailsClosedOnAuthorityOutage(t *testing.T) {
	p, _, ledger, stream := policyRelay(t, false)
	p.meter = &unavailablePolicyBackend{Backend: ledger, SharingBackend: ledger}
	w := httptest.NewRecorder()
	p.handleWebProxy(w, relayRequest(relayJWT(t, p, "owner@example.com"), ""))
	if w.Code != 503 || w.Header().Get("Tunn-Limit-Reason") != "policy_unavailable" {
		t.Fatalf("outage=%d %s", w.Code, w.Body)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if len(stream.sentMsgs) != 0 {
		t.Fatal("outage reached origin")
	}
}

func TestPolicyAPIOnlyOwnerAndBoundedAtomicConfiguration(t *testing.T) {
	p, tunnel, _, _ := policyRelay(t, false)
	request := func(method, body, token, origin, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://"+host+"/api/endpoints/api/policy", strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		p.handleMeteringAPI(w, r)
		return w
	}
	owner := relayJWT(t, p, "owner@example.com")
	valid := `{"headers":{"rewrite":[{"name":"X-Test","value":"configured"}]}}`
	for _, tc := range []struct {
		method, body, token, origin, host string
		want                              int
	}{
		{"PUT", valid, "", "", "tunn.test", 401},
		{"PUT", valid, relayJWT(t, p, "stranger@example.com"), "", "tunn.test", 404},
		{"PUT", valid, "tunn_ep_invalid", "", "tunn.test", 401},
		{"PUT", valid, owner, "https://evil.example", "tunn.test", 403},
		{"PUT", valid, owner, "", "api.tunn.test", 403},
		{"PUT", valid, owner, "", "tunn.test", 200},
		{"PUT", `{"headers":{"remove":["Authorization"]}}`, owner, "", "tunn.test", 400},
		{"PUT", valid + " {}", owner, "", "tunn.test", 400},
		{"PUT", strings.Repeat(" ", trafficpolicy.MaxJSONBytes+1), owner, "", "tunn.test", 400},
		{"POST", valid, owner, "", "tunn.test", 405},
		{"GET", "", relayJWT(t, p, "stranger@example.com"), "", "tunn.test", 404},
	} {
		w := request(tc.method, tc.body, tc.token, tc.origin, tc.host)
		if w.Code != tc.want {
			t.Errorf("%s want %d got %d: %s", tc.method, tc.want, w.Code, w.Body)
		}
	}
	w := request("GET", "", owner, "", "tunn.test")
	var policy trafficpolicy.Policy
	if err := json.Unmarshal(w.Body.Bytes(), &policy); err != nil || len(policy.Headers.Rewrite) != 1 {
		t.Fatalf("invalid mutation altered policy: %s %v", w.Body, err)
	}
	if tunnel.AccountID == "" {
		t.Fatal("fixture owner missing")
	}
	if w := request("DELETE", "", owner, "", "tunn.test"); w.Code != 200 || strings.Contains(w.Body.String(), "configured") {
		t.Fatalf("clear=%d %s", w.Code, w.Body)
	}
}

func TestPolicyMCPKeepsExistingAuthAndRunsBeforeOrigin(t *testing.T) {
	f := newMCPOAuthFixture(t)
	out, err := f.p.meter.(metering.SharingBackend).Sharing(context.Background(), &meterpb.SharingRequest{Operation: "register", Owner: f.tunnel.AccountID, Endpoint: "tools", Mode: "policy-only"})
	if err != nil {
		t.Fatal(err)
	}
	f.tunnel.PolicyResourceID = out.Resources[0].Id
	relayPolicy(t, f.p, f.tunnel, `{"rate_limits":{"per_account":{"requests_per_minute":1,"burst":1}}}`)
	owner := relayJWT(t, f.p, "owner@example.com")
	for i, want := range []int{200, 429} {
		w := f.request("POST", "https://tools.tunn.test/mcp", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "application/json", owner, nil)
		if w.Code != want {
			t.Fatalf("MCP request %d=%d want %d %s", i, w.Code, want, w.Body)
		}
	}
	if f.forwarded != 1 {
		t.Fatalf("MCP forwarded=%d", f.forwarded)
	}
	list, err := f.p.meter.(metering.SharingBackend).Sharing(context.Background(), &meterpb.SharingRequest{Operation: "list", Owner: f.tunnel.AccountID})
	if err != nil || len(list.Resources) != 0 {
		t.Fatalf("MCP policy exposed as web ACL: %v %v", list, err)
	}
}

func TestPolicyMCPRegistrationBindsGeneration(t *testing.T) {
	f := newMCPOAuthFixture(t)
	s := f.p.tunnelServer
	s.sharing = f.p.meter.(metering.SharingBackend)
	var registered *TunnelConnection
	stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
	stream.onSend = func(msg *pb.TunnelMessage) error {
		if response := msg.GetRegisterResponse(); response != nil && response.Success {
			registered, _ = s.GetTunnel("policy-mcp")
		}
		return stream.mockTunnelStream.Send(msg)
	}
	stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "policy-mcp", TargetUrl: "mcp", AuthToken: relayJWT(t, f.p, "owner@example.com"), TunnelKey: f.p.config.WellKnownKey, AllowedEmails: []string{"owner@example.com"}}}}
	close(stream.recvQueue)
	_ = s.EstablishTunnel(stream)
	if registered == nil || registered.PolicyResourceID == "" || registered.ResourceID != "" {
		t.Fatalf("MCP generation=%+v", registered)
	}
	relayPolicy(t, f.p, registered, `{"rate_limits":{"per_ip":{"requests_per_minute":10,"burst":1}}}`)
}

func TestPolicyRemoteAuthorityPreservesOwnerAndRateDecision(t *testing.T) {
	p, tunnel, ledger, _ := policyRelay(t, false)
	relayPolicy(t, p, tunnel, `{"rate_limits":{"per_account":{"requests_per_minute":1,"burst":1}}}`)
	const secret = "policy-node-fixture"
	server := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor(secret)))
	meterpb.RegisterMeteringServer(server, ledger)
	listener := prodAuthRPCListener{bufconn.Listen(1 << 20)}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	conn, err := grpc.NewClient("passthrough:///policy-authority", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(metadata.AppendToOutgoingContext(ctx, "x-node-secret", secret), method, req, reply, cc, opts...)
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	remote := &metering.Remote{Connection: func() *grpc.ClientConn { return conn }}
	p.meter = remote
	for _, want := range []int{200, 429} {
		w := httptest.NewRecorder()
		p.handleWebProxy(w, relayRequest(relayJWT(t, p, "owner@example.com"), ""))
		if w.Code != want {
			t.Fatalf("remote rate=%d want %d: %s", w.Code, want, w.Body)
		}
	}
	if _, err = remote.EndpointPolicy(context.Background(), &meterpb.EndpointPolicyRequest{Operation: "get", Owner: "other-owner", Endpoint: tunnel.TunnelID}); err == nil {
		t.Fatal("remote cross-owner read")
	}
}

type policyHostTransport struct{ transport http.RoundTripper }

func (t policyHostTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = "tunn.test"
	return t.transport.RoundTrip(r)
}

func TestPolicyLoopbackOwnerCLIToTLSRelayToRealOrigin(t *testing.T) {
	f := newMCPOAuthFixture(t)
	p := f.p
	p.tunnelServer.sharing = p.meter.(metering.SharingBackend)
	var hits atomic.Int64
	wsFixture := &webSocketFixture{closes: make(chan []byte, 10)}
	wsPolicyHeader := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/echo" {
			hits.Add(1)
			wsPolicyHeader <- r.Header.Get("X-Policy")
			wsFixture.ServeHTTP(w, r)
			return
		}
		hits.Add(1)
		data, _ := io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(struct {
			Headers http.Header
			Body    string
		}{r.Header, string(data)})
	}))
	defer origin.Close()
	gs := grpc.NewServer()
	pb.RegisterTunnelServiceServer(gs, p.tunnelServer)
	p.grpcServer = gs
	relay := httptest.NewUnstartedServer(p.createHTTP2Router(p.createHandler()))
	relay.EnableHTTP2 = true
	relay.StartTLS()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan string, 1)
	publisher := &client.ServeClient{TunnelID: "policy-loopback", TargetURL: origin.URL, ServerAddr: relay.Listener.Addr().String(), AuthToken: relayJWT(t, p, "owner@example.com"), TunnelKey: p.config.WellKnownKey, Insecure: true, Quiet: true, RequireSharing: true, OnRegistered: func(u string) {
		select {
		case ready <- u:
		default:
		}
	}}
	go func() { done <- publisher.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("publisher shutdown timeout")
		}
		gs.Stop()
		relay.Close()
	})
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("owner publisher did not register")
	}
	tunnel, ok := p.tunnelServer.GetTunnel("policy-loopback")
	if !ok || tunnel.ResourceID == "" {
		t.Fatal("real registration did not bind owner generation")
	}
	policy, err := trafficpolicy.Decode([]byte(`{"headers":{"rewrite":[{"name":"X-Policy","value":"owner"}],"remove":["X-Remove"]},"rate_limits":{"per_ip":{"requests_per_minute":1,"burst":1},"per_account":{"requests_per_minute":1,"burst":1}}}`))
	if err != nil {
		t.Fatal(err)
	}
	hc := relay.Client()
	ownerHTTP := *hc
	ownerHTTP.Transport = policyHostTransport{hc.Transport}
	management := &client.ManagementClient{ServerURL: relay.URL, OwnerToken: relayJWT(t, p, "owner@example.com"), HTTPClient: &ownerHTTP}
	var output bytes.Buffer
	if err = client.ExecutePolicy(ctx, "set", "policy-loopback", policy, management, &output); err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{401, 200, 429} {
		r, _ := http.NewRequest("POST", relay.URL+"/", strings.NewReader("payload"))
		r.Host = "policy-loopback.tunn.test"
		r.Header.Set("X-Policy", "visitor")
		r.Header.Set("X-Remove", "gone")
		if i == 0 {
			r.Header.Set("Tunn-Authorization", "Bearer invalid-fixture")
		}
		if i > 0 {
			r.Header.Set("Tunn-Authorization", "Bearer "+relayJWT(t, p, "owner@example.com"))
		}
		response, err := hc.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("TLS request=%d want %d body=%s", response.StatusCode, want, body)
		}
		if want == 200 {
			var echoed struct {
				Headers http.Header
				Body    string
			}
			if err = json.Unmarshal(body, &echoed); err != nil {
				t.Fatal(err)
			}
			if echoed.Headers.Get("X-Policy") != "owner" || echoed.Headers.Get("X-Remove") != "" || echoed.Headers.Get("Tunn-Authorization") != "" || echoed.Body != "payload" {
				t.Fatalf("origin received=%+v", echoed)
			}
		}
		if want == 429 && response.Header.Get("Retry-After") == "" {
			t.Fatal("missing Retry-After")
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("real origin hits=%d", hits.Load())
	}
	if err = client.ExecutePolicy(ctx, "clear", "policy-loopback", nil, management, io.Discard); err != nil {
		t.Fatal(err)
	}
	wsPolicy, err := trafficpolicy.Decode([]byte(`{"headers":{"rewrite":[{"name":"X-Policy","value":"ws-owner"}]},"rate_limits":{"per_ip":{"requests_per_minute":1,"burst":1}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = client.ExecutePolicy(ctx, "set", "policy-loopback", wsPolicy, management, io.Discard); err != nil {
		t.Fatal(err)
	}
	dialWS := func() (net.Conn, *bufio.Reader, *http.Response) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", relay.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		req, _ := http.NewRequest("GET", relay.URL+"/echo", nil)
		req.Host = "policy-loopback.tunn.test"
		req.Header.Set("Tunn-Authorization", "Bearer "+relayJWT(t, p, "owner@example.com"))
		req.Header.Set("X-Policy", "visitor")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		if err = req.Write(conn); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		res, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatal(err)
		}
		return conn, reader, res
	}
	ws, reader, res := dialWS()
	if res.StatusCode != 101 {
		t.Fatalf("policy WS handshake=%d", res.StatusCode)
	}
	select {
	case header := <-wsPolicyHeader:
		if header != "ws-owner" {
			t.Fatalf("WS origin header=%s", header)
		}
	case <-time.After(time.Second):
		t.Fatal("WS origin did not observe header")
	}
	for _, payload := range [][]byte{[]byte("one"), []byte("two")} {
		if _, err = ws.Write(fixtureFrame(1, true, true, payload)); err != nil {
			t.Fatal(err)
		}
		expectWireFrame(t, reader, 1, payload)
	}
	denied, _, res := dialWS()
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	_ = denied.Close()
	if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("second WS handshake=%d %s", res.StatusCode, body)
	}
	_ = ws.Close()
	if hits.Load() != 2 {
		t.Fatalf("HTTP+WS origin hits=%d want 2", hits.Load())
	}
}

type revokeBeforePolicyBackend struct {
	metering.Backend
	metering.SharingBackend
	metering.PolicyBackend
}

func (b *revokeBeforePolicyBackend) Resolve(ctx context.Context, in *meterpb.ResolveRequest) (*meterpb.Grant, error) {
	g, err := b.Backend.Resolve(ctx, in)
	if err == nil && g.Id != "" {
		_, err = b.Backend.RevokeGrant(ctx, g)
	}
	return g, err
}

func TestPolicyInvalidGrantsNeverConsumeEitherBucket(t *testing.T) {
	for _, kind := range []string{"revoked", "expired", "revoked-after-resolve"} {
		t.Run(kind, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			p, tunnel := f.p, f.tunnel
			ledger := p.meter.(*metering.Store)
			out, err := ledger.Sharing(context.Background(), &meterpb.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Mode: "policy-only"})
			if err != nil {
				t.Fatal(err)
			}
			tunnel.PolicyResourceID = out.Resources[0].Id
			relayPolicy(t, p, tunnel, `{"rate_limits":{"per_ip":{"requests_per_minute":1,"burst":1},"per_account":{"requests_per_minute":1,"burst":1}}}`)
			raw := "tunn_gr_policy-" + kind
			digest := sha256.Sum256([]byte(raw))
			g, err := ledger.CreateGrant(context.Background(), &meterpb.Grant{Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "revoked":
				if _, err = ledger.RevokeGrant(context.Background(), g); err != nil {
					t.Fatal(err)
				}
			case "expired":
				expired := time.Now().Add(-time.Second).UnixMilli()
				if _, err = f.p.mcpOAuth.db.Exec(`UPDATE meter_grants SET expires=?,data=json_set(CAST(data AS TEXT),'$.expires_at',?) WHERE id=?`, expired, expired, g.Id); err != nil {
					t.Fatal(err)
				}
			case "revoked-after-resolve":
				p.meter = &revokeBeforePolicyBackend{Backend: ledger, SharingBackend: ledger, PolicyBackend: ledger}
			}
			w := f.request("POST", "https://tools.tunn.test/mcp", `{}`, "application/json", raw, nil)
			if w.Code != 403 || f.forwarded != 0 {
				t.Fatalf("invalid grant=%d forwarded=%d %s", w.Code, f.forwarded, w.Body)
			}
			var buckets int
			if err = f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM endpoint_policy_buckets`).Scan(&buckets); err != nil || buckets != 0 {
				t.Fatalf("unauthorized grant consumed policy: %d %v", buckets, err)
			}
			w = f.request("POST", "https://tools.tunn.test/mcp", `{}`, "application/json", relayJWT(t, p, "owner@example.com"), nil)
			if w.Code != 200 || f.forwarded != 1 {
				t.Fatalf("valid owner after invalid grant=%d %s", w.Code, w.Body)
			}
		})
	}
}

func TestPolicyRepeatedConnectionHeadersCannotDiscardOwnerEdit(t *testing.T) {
	for _, kind := range []string{"buffered", "streamed", "websocket"} {
		t.Run(kind, func(t *testing.T) {
			p, tunnel, _, stream := policyRelay(t, kind != "buffered")
			relayPolicy(t, p, tunnel, `{"headers":{"rewrite":[{"name":"X-Service","value":"owner"}]}}`)
			r := relayRequest(relayJWT(t, p, "owner@example.com"), "")
			r.Header["Connection"] = []string{"keep-alive", "X-Service"}
			if kind == "websocket" {
				r.Method = "GET"
				r.Header["Connection"] = []string{"Upgrade", "x-service"}
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Sec-WebSocket-Version", "13")
				r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			}
			w := httptest.NewRecorder()
			p.handleWebProxy(w, r)
			if w.Code != 400 {
				t.Fatalf("connection nomination=%d %s", w.Code, w.Body)
			}
			stream.mu.Lock()
			defer stream.mu.Unlock()
			if len(stream.sentMsgs) != 0 {
				t.Fatal("conflict reached origin")
			}
		})
	}
}

func TestPolicyOwnerBrowserLoginObtainsUsableSeparateCredential(t *testing.T) {
	t.Setenv("TUNN_CONFIG_DIR", t.TempDir())
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := newMCPOAuthFixtureWithDB(t, db)
	p := f.p
	p.devices, err = newDeviceCredentialStore(db)
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.meter.(metering.SharingBackend).Sharing(context.Background(), &meterpb.SharingRequest{Operation: "register", Owner: f.tunnel.AccountID, Endpoint: "tools", Mode: "policy-only"})
	if err != nil {
		t.Fatal(err)
	}
	f.tunnel.PolicyResourceID = out.Resources[0].Id
	relay := httptest.NewTLSServer(p.createHandler())
	defer relay.Close()
	hc := relay.Client()
	ownerHTTP := *hc
	ownerHTTP.Transport = policyHostTransport{hc.Transport}
	l := &client.LoginClient{PolicyOwner: true, ServerAddr: relay.Listener.Addr().String(), HTTPClient: &ownerHTTP, Output: io.Discard}
	cookie := securityCookie(t, p, "owner@example.com")
	l.OpenBrowser = func(link string) {
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		code := u.Query().Get("code")
		page := f.request("GET", "https://tunn.test/login?code="+url.QueryEscape(code), "", "", "", cookie)
		if page.Code != 200 || !strings.Contains(page.Body.String(), "account administration access") {
			t.Fatalf("owner consent page=%d", page.Code)
		}
		match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
		if len(match) != 2 {
			t.Fatal("owner confirmation missing CSRF")
		}
		form := url.Values{"code": {code}, "csrf_token": {match[1]}}
		authorized := f.request("POST", "https://tunn.test/auth/device/authorize", form.Encode(), "application/x-www-form-urlencoded", "", cookie)
		if authorized.Code != 200 {
			t.Fatalf("browser owner authorization=%d %s", authorized.Code, authorized.Body)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = l.Run(ctx); err != nil {
		t.Fatal(err)
	}
	token, err := client.LoadPolicyOwnerToken(relay.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := &client.ManagementClient{ServerURL: relay.URL, OwnerToken: token, HTTPClient: &ownerHTTP}
	if err = client.ExecutePolicy(ctx, "set", "tools", &trafficpolicy.Policy{}, c, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyScopedDeviceCredentialCannotManagePolicies(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		r := httptest.NewRequest(method, "https://tunn.test/api/endpoints/tools/policy", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+token.Access)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("scoped device %s policy=%d %s", method, w.Code, w.Body)
		}
	}
}
