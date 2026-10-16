package host

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/ehrlich-b/tunn/internal/storage"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/metering"
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

func setHostPolicy(t *testing.T, p *ProxyServer, endpoint string, allow, deny []string) {
	t.Helper()
	_, err := p.ipPolicyBackend().IPPolicy(context.Background(), &mp.IPPolicyRequest{Operation: "set", Owner: "ad38bf44-0c4a-40ce-bdee-2d8579bf63cc", Endpoint: endpoint, AllowCidrs: allow, DenyCidrs: deny})
	if err != nil {
		t.Fatal(err)
	}
}
func policyOpen(p *ProxyServer, peer, credential, kind string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://api.tunn.test/", nil)
	r.RemoteAddr = peer
	switch kind {
	case "owner", "guest":
		r.AddCookie(&http.Cookie{Name: authCookieName, Value: credential})
	case "grant", "endpoint", "mcp":
		r.Header.Set("Tunn-Authorization", "Bearer "+credential)
	case "connect":
		r.Method = "CONNECT"
		r.Header.Set("Tunn-Authorization", "Bearer "+credential)
	case "websocket":
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
	}
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}
func TestIPPolicyIngressBeforeCredentialsAndSharing(t *testing.T) {
	p, tunnel, ledger, stream := webSharingFixture(t)
	owner := relayJWT(t, p, "owner@example.com")
	guest := relayJWT(t, p, "alice@example.com")
	if w := sharingCall(t, p, "POST", "api", owner, `{"email":"alice@example.com"}`); w.Code != 200 {
		t.Fatal(w)
	}
	_, grant := relayGrant(t, ledger, 20, 10000)
	endpoint := "fixture-endpoint-secret"
	digest := sha256.Sum256([]byte(endpoint))
	tunnel.updateAccessTokenDigest(digest[:])
	setHostPolicy(t, p, "", []string{"192.0.2.0/24", "2001:db8::/32"}, []string{"192.0.2.42/32", "2001:db8::42/128"})
	for _, tt := range []struct{ kind, credential string }{{"anonymous", ""}, {"owner", owner}, {"guest", guest}, {"grant", grant}, {"endpoint", endpoint}, {"mcp", "tunn_mcp_invalid"}, {"connect", grant}, {"websocket", ""}} {
		for _, peer := range []string{"198.51.100.9:443", "192.0.2.42:9000", "[2001:db8::42]:443", "unknown"} {
			before := len(stream.sentMsgs)
			w := policyOpen(p, peer, tt.credential, tt.kind, nil)
			if w.Code != 403 || w.Header().Get("Location") != "" || w.Header().Get("Tunn-Limit-Reason") != "ip_policy_denied" || !strings.Contains(w.Body.String(), "Your IP address") {
				t.Fatalf("%s %s: %d %s", tt.kind, peer, w.Code, w.Body.String())
			}
			if len(stream.sentMsgs) != before {
				t.Fatal("denied request reached publisher")
			}
		}
	}
	for _, peer := range []string{"192.0.2.1:443", "[2001:db8::1]:443", "[::ffff:192.0.2.1]:443"} {
		for _, tt := range []struct{ kind, credential string }{{"owner", owner}, {"guest", guest}, {"grant", grant}, {"endpoint", endpoint}} {
			if w := policyOpen(p, peer, tt.credential, tt.kind, nil); w.Code != 200 {
				t.Fatalf("allowed %s %s: %d %s", tt.kind, peer, w.Code, w.Body.String())
			}
		}
	}
	if w := policyOpen(p, "192.0.2.1:443", "", "anonymous", nil); w.Code != 302 {
		t.Fatal("allow bypassed private authentication", w)
	}
	// Explicit public remains restricted by the IP gate.
	tunnel.updateAccessTokenDigest(nil)
	if _, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: "api", Mode: "public"}); err != nil {
		t.Fatal(err)
	}
	if w := policyOpen(p, "192.0.2.1:443", "", "anonymous", nil); w.Code != 200 {
		t.Fatal(w)
	}
	if w := policyOpen(p, "198.51.100.1:443", "", "anonymous", nil); w.Code != 403 {
		t.Fatal("public bypass", w)
	}
	setHostPolicy(t, p, "api", nil, nil)
	if w := policyOpen(p, "198.51.100.1:443", "", "anonymous", nil); w.Code != 200 {
		t.Fatal("explicit empty override", w)
	}
	if _, err := ledger.IPPolicy(context.Background(), &mp.IPPolicyRequest{Operation: "delete", Owner: tunnel.AccountID, Endpoint: "api"}); err != nil {
		t.Fatal(err)
	}
	if w := policyOpen(p, "198.51.100.1:443", "", "anonymous", nil); w.Code != 403 {
		t.Fatal("delete did not inherit", w)
	}
	events := relayExport(t, ledger)
	found := false
	for _, event := range events.Events {
		if event.Reason == "ip_policy_denied" {
			found = true
			if event.Allowed || event.Forwarded {
				t.Fatal("denial audited as admitted")
			}
		}
	}
	if !found {
		t.Fatal("IP denial missing from metadata audit")
	}
}
func TestIPPolicySpoofingAndSignedRelayPeer(t *testing.T) {
	p, _, _, _ := webSharingFixture(t)
	p.config.NodeSecret = "fixture-node-secret"
	setHostPolicy(t, p, "api", []string{"192.0.2.0/24", "2001:db8::/32"}, nil)
	owner := relayJWT(t, p, "owner@example.com")
	headers := map[string]string{"X-Forwarded-For": "192.0.2.1", "X-Real-IP": "192.0.2.1", "Forwarded": "for=192.0.2.1", "Fly-Client-IP": "192.0.2.1", relayForwardedFor: "192.0.2.1", relayForwardedProto: "https", relayForwardedSignature: "forged"}
	if w := policyOpen(p, "198.51.100.1:1234", owner, "owner", headers); w.Code != 403 {
		t.Fatal("public headers bypassed policy", w)
	}
	for _, peer := range []string{"192.0.2.1", "2001:db8::1"} {
		headers[relayForwardedFor] = peer
		headers[relayForwardedSignature] = p.forwardingSignature("api.tunn.test", peer, "https")
		if w := policyOpen(p, "198.51.100.1:1234", owner, "owner", headers); w.Code != 200 {
			t.Fatal("authenticated relay IP lost", w)
		}
		headers[relayForwardedSignature] = p.forwardingSignature("other.tunn.test", peer, "https")
		if w := policyOpen(p, "198.51.100.1:1234", owner, "owner", headers); w.Code != 403 {
			t.Fatal("cross-host signature accepted", w)
		}
	}
	// A blocked first-hop client stays blocked even when the next socket is allowed.
	headers[relayForwardedFor] = "198.51.100.1"
	headers[relayForwardedSignature] = p.forwardingSignature("api.tunn.test", "198.51.100.1", "https")
	if w := policyOpen(p, "192.0.2.1:1234", owner, "owner", headers); w.Code != 403 {
		t.Fatal("relay socket replaced signed client IP", w)
	}
}

type unavailableIPPolicy struct{ metering.Backend }

func (unavailableIPPolicy) IPPolicy(context.Context, *mp.IPPolicyRequest) (*mp.IPPolicy, error) {
	return nil, errors.New("fixture authority outage")
}
func TestIPPolicyAuthorityFailureClosesIngress(t *testing.T) {
	p, _, ledger, _ := webSharingFixture(t)
	p.meter = unavailableIPPolicy{ledger}
	if w := policyOpen(p, "192.0.2.1:443", relayJWT(t, p, "owner@example.com"), "owner", nil); w.Code != 503 {
		t.Fatal(w)
	}
	p.meter = &metering.Remote{Connection: func() *grpc.ClientConn { return nil }}
	if w := policyOpen(p, "192.0.2.1:443", "", "anonymous", nil); w.Code != 503 {
		t.Fatal(w)
	}
}
func policyAPICall(p *ProxyServer, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://tunn.test"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}
func TestIPPolicyAPIAuthOriginValidationAndIsolation(t *testing.T) {
	p, _, ledger, _ := webSharingFixture(t)
	owner := relayJWT(t, p, "owner@example.com")
	stranger := relayJWT(t, p, "stranger@example.com")
	_, grant := relayGrant(t, ledger, 10, 1000)
	for _, token := range []string{"", "garbage", grant, p.config.NodeSecret} {
		if w := policyAPICall(p, "PUT", "/api/ip-policy/api", token, `{"deny_cidrs":["0.0.0.0/0"]}`); w.Code != 401 {
			t.Fatal("non-owner credential", w)
		}
	}
	if w := policyAPICall(p, "PUT", "/api/ip-policy/api", owner, `{"allow_cidrs":["192.0.2.99/24"],"deny_cidrs":["192.0.2.42/32"]}`); w.Code != 200 || !strings.Contains(w.Body.String(), "192.0.2.0/24") {
		t.Fatal(w)
	}
	if w := policyAPICall(p, "GET", "/api/ip-policy/api", stranger, ""); w.Code != 200 || strings.Contains(w.Body.String(), "192.0.2.0/24") {
		t.Fatal("cross owner disclosure", w)
	}
	if w := policyAPICall(p, "DELETE", "/api/ip-policy/api", stranger, ""); w.Code != 200 {
		t.Fatal(w)
	}
	if w := policyAPICall(p, "GET", "/api/ip-policy/api", owner, ""); !strings.Contains(w.Body.String(), "192.0.2.0/24") {
		t.Fatal("cross owner deletion", w)
	}
	for _, body := range []string{`{"allow_cidrs":["bad"]}`, `{"deny_cidrs":["::/129"]}`, `{"owner":"stranger"}`, `{"allow_cidrs":["192.0.2.0/24"]} {}`, `[]`, `null`} {
		if w := policyAPICall(p, "PUT", "/api/ip-policy/api", owner, body); w.Code != 400 {
			t.Fatalf("body %s: %d", body, w.Code)
		}
	}
	if w := policyAPICall(p, "PATCH", "/api/ip-policy/api", owner, ""); w.Code != 405 {
		t.Fatal(w)
	}
	if w := policyAPICall(p, "GET", "/api/ip-policy/bad/name", owner, ""); w.Code != 404 {
		t.Fatal(w)
	}
	for _, origin := range []string{"https://api.tunn.test", "https://attacker.example.invalid"} {
		r := httptest.NewRequest("PUT", "https://tunn.test/api/ip-policy/api", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+owner)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("foreign origin changed policy", w)
		}
	}
	if w := policyAPICall(p, "PUT", "/api/ip-policy", owner, `{"deny_cidrs":["0.0.0.0/0","::/0"]}`); w.Code != 200 {
		t.Fatal(w)
	}
	if w := policyAPICall(p, "GET", "/api/ip-policy", owner, ""); w.Code != 200 {
		t.Fatal("blocked owner cannot recover", w)
	}
	if w := policyAPICall(p, "DELETE", "/api/ip-policy/api", owner, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"inherited":true`) {
		t.Fatal(w)
	}
}
func TestIPPolicyPageCSRFValidationAndRecovery(t *testing.T) {
	p, _, _, _ := webSharingFixture(t)
	cookie := &http.Cookie{Name: authCookieName, Value: relayJWT(t, p, "owner@example.com")}
	get := httptest.NewRequest("GET", "https://tunn.test/account/ip-policy?endpoint=api", nil)
	get.AddCookie(cookie)
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, get)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "inherits the account default") {
		t.Fatal(w)
	}
	token := hiddenMCPField(t, w.Body.String(), "csrf_token")
	for _, valid := range []bool{false, true} {
		form := url.Values{"action": {"set"}, "allow_cidrs": {"192.0.2.0/24\n2001:db8::/32"}, "deny_cidrs": {"192.0.2.42/32"}}
		if valid {
			form.Set("csrf_token", token)
		}
		r := httptest.NewRequest("POST", get.URL.String(), strings.NewReader(form.Encode()))
		r.AddCookie(cookie)
		r.Header.Set("Origin", "https://tunn.test")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w = httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if valid && w.Code != 303 || !valid && w.Code != 403 {
			t.Fatal("CSRF", w)
		}
	}
	form := url.Values{"action": {"set"}, "csrf_token": {token}, "allow_cidrs": {"bad-network"}}
	r := httptest.NewRequest("POST", get.URL.String(), strings.NewReader(form.Encode()))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://tunn.test")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid CIDR") || !strings.Contains(w.Body.String(), "bad-network") {
		t.Fatal("validation not visible", w)
	}
	w = httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, get)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "192.0.2.0/24") {
		t.Fatal("invalid form changed policy", w)
	}
	for _, path := range []string{"/account/ip-policy", "/docs/ip-restrictions"} {
		r := httptest.NewRequest("GET", "https://tunn.test"+path, nil)
		w = httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if path == "/account/ip-policy" && w.Code != 302 || path == "/docs/ip-restrictions" && w.Code != 200 {
			t.Fatal(w)
		}
	}
}

func TestIPPolicyInternalRPCUsesNodeAuthority(t *testing.T) {
	_, _, ledger, _ := webSharingFixture(t)
	listener := prodAuthRPCListener{bufconn.Listen(65536)}
	defer listener.Close()
	secret := "fixture-policy-node-secret"
	server := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor(secret)))
	mp.RegisterMeteringServer(server, ledger)
	go server.Serve(listener)
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///ip-policy-rpc", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
		return listener.DialContext(ctx)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	remote := &metering.Remote{Connection: func() *grpc.ClientConn { return conn }}
	ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(context.Background(), "x-node-secret", secret), 5*time.Second)
	defer cancel()
	out, err := remote.IPPolicy(ctx, &mp.IPPolicyRequest{Operation: "set", Owner: "fixture-owner", Endpoint: "api", AllowCidrs: []string{"2001:db8::/32"}})
	if err != nil || len(out.AllowCidrs) != 1 {
		t.Fatal(out, err)
	}
	if _, err := remote.IPPolicy(ctx, &mp.IPPolicyRequest{Operation: "set", Owner: "fixture-owner", Endpoint: "api", AllowCidrs: []string{"invalid"}}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("RPC lost validation", err)
	}
	// Direct interceptor invocation uses a unique fixture peer, avoiding shared
	// blacklist state while proving this new method cannot omit node credentials.
	interceptor := nodeSecretInterceptor(secret)
	called := false
	_, err = interceptor(metadata.NewIncomingContext(context.Background(), metadata.MD{}), &mp.IPPolicyRequest{}, &grpc.UnaryServerInfo{FullMethod: mp.Metering_IPPolicy_FullMethodName}, func(context.Context, any) (any, error) { called = true; return nil, nil })
	if called || status.Code(err) != codes.Unauthenticated {
		t.Fatal("unauthenticated policy RPC", err)
	}
}

func TestIPPolicyDomainAppAndCallbackBeforeAuthentication(t *testing.T) {
	p, tunnel, _, db := appProxyFixtureDB(t)
	ledger, err := metering.New(db)
	if err != nil {
		t.Fatal(err)
	}
	p.meter = ledger
	appResource(t, p, tunnel, "private")
	setHostPolicy(t, p, tunnel.TunnelID, []string{"192.0.2.0/24"}, nil)
	cookie := appSessionCookie(t, p, appOwnerEmail, "github", true, appHost)
	for _, path := range []string{"/report", appCallback + "?token=invalid"} {
		for _, authenticated := range []bool{false, true} {
			r := httptest.NewRequest("GET", "https://"+appHost+path, nil)
			r.RemoteAddr = "198.51.100.1:1234"
			if authenticated {
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, r)
			if w.Code != 403 || w.Header().Get("Tunn-Limit-Reason") != "ip_policy_denied" || w.Header().Get("Location") != "" {
				t.Fatal("domain authentication bypassed policy", w)
			}
		}
	}
	for _, authenticated := range []bool{false, true} {
		r := httptest.NewRequest("GET", "https://"+appHost+"/report", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		want := 302
		if authenticated {
			r.AddCookie(cookie)
			want = 200
		}
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("allowed app request: %d want %d: %s", w.Code, want, w.Body)
		}
	}
}

func TestIPPolicyValidMCPOAuthCannotBypassRestrictions(t *testing.T) {
	f := newMCPOAuthFixture(t)
	c := discoverMCPClient(t, f)
	token := c.accessToken(t)
	_, err := f.p.meter.IPPolicy(context.Background(), &mp.IPPolicyRequest{Operation: "set", Owner: f.tunnel.AccountID, Endpoint: "tools", AllowCidrs: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		peer string
		want int
	}{{"198.51.100.1:1234", 403}, {"192.0.2.1:1234", 200}} {
		r := httptest.NewRequest("POST", c.resource, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		r.RemoteAddr = tt.peer
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		before := f.forwarded
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != tt.want || tt.want == 403 && f.forwarded != before || tt.want == 200 && f.forwarded != before+1 {
			t.Fatalf("MCP policy: peer=%s status=%d forwarded=%d", tt.peer, w.Code, f.forwarded)
		}
	}
}

func TestIPPolicyStreamAdmissionRetainedAndReconnectDenied(t *testing.T) {
	for _, protocol := range []string{"http", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			p, tunnel, _, stream := meteringRelay(t, true, "")
			tunnel.EndpointProtocol = protocol
			tunnel.Capabilities[common.CapabilityConnectionStreamV1] = true
			setHostPolicy(t, p, "api", []string{"192.0.2.0/24", "2001:db8::/32"}, nil)
			stream.hook = func(msg *pb.TunnelMessage) error {
				if end := msg.GetConnectionHalfClose(); end != nil {
					// Change policy after admission, before sending the response.
					_, err := p.meter.IPPolicy(context.Background(), &mp.IPPolicyRequest{Operation: "set", Owner: tunnel.AccountID, Endpoint: "api", DenyCidrs: []string{"0.0.0.0/0", "::/0"}})
					if err != nil {
						return err
					}
					id := end.ConnectionId
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/event-stream"}}}}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte("data: admitted\n\n")}}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id}}})
				}
				return nil
			}
			token := relayJWT(t, p, "owner@example.com")
			request := func(peer string) *httptest.ResponseRecorder {
				method, path := "GET", "/events"
				if protocol == "tcp" {
					method, path = "CONNECT", common.TCPConnectPath
				}
				r := httptest.NewRequest("GET", "https://api.tunn.test"+path, nil)
				r.Method = method
				r.RemoteAddr = peer
				r.Header.Set("Authorization", "Bearer "+token)
				if protocol == "tcp" {
					r.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
				}
				w := httptest.NewRecorder()
				p.createHandler().ServeHTTP(w, r)
				return w
			}
			if w := request("198.51.100.1:1234"); w.Code != 403 {
				t.Fatal("blocked stream admitted", w)
			}
			if len(stream.sentMsgs) != 0 {
				t.Fatal("blocked stream reached publisher")
			}
			if w := request("[2001:db8::1]:1234"); w.Code != 200 || w.Body.String() != "data: admitted\n\n" {
				t.Fatal("policy update interrupted admitted stream", w)
			}
			stream.mu.Lock()
			before := len(stream.sentMsgs)
			stream.mu.Unlock()
			if w := request("[2001:db8::1]:1234"); w.Code != 403 {
				t.Fatal("reconnect retained old policy", w)
			}
			stream.mu.Lock()
			defer stream.mu.Unlock()
			if len(stream.sentMsgs) != before {
				t.Fatal("blocked reconnect reached publisher")
			}
		})
	}
}

func TestIPPolicyWebSocketAdmissionRetainedAndReconnectDenied(t *testing.T) {
	p, tunnel, _, stream := webSharingFixture(t)
	tunnel.Capabilities = map[string]bool{common.CapabilityWebSocketV1: true}
	opened := make(chan string, 1)
	stream.hook = func(msg *pb.TunnelMessage) error {
		if open := msg.GetConnectionOpen(); open != nil {
			opened <- open.ConnectionId
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 101, Headers: map[string]string{"Upgrade": "websocket", "Connection": "upgrade", "Sec-WebSocket-Accept": common.WebSocketAccept("dGhlIHNhbXBsZSBub25jZQ==")}}}}})
		}
		return nil
	}
	server := httptest.NewServer(p.createHandler())
	defer server.Close()
	token := relayJWT(t, p, "owner@example.com")
	dial := func() (net.Conn, *bufio.Reader, *http.Response) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		r, _ := http.NewRequest("GET", server.URL+"/socket", nil)
		r.Host = "api.tunn.test"
		r.Header = http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}, "Sec-Websocket-Version": {"13"}, "Authorization": {"Bearer " + token}, "X-Forwarded-For": {"192.0.2.1"}}
		if err := r.Write(conn); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		response, err := http.ReadResponse(reader, r)
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		return conn, reader, response
	}
	setHostPolicy(t, p, "api", []string{"192.0.2.0/24"}, nil)
	conn, _, response := dial()
	conn.Close()
	if response.StatusCode != 403 || len(opened) != 0 {
		t.Fatal("spoofed WebSocket peer admitted", response.StatusCode)
	}
	setHostPolicy(t, p, "api", []string{"127.0.0.0/8"}, nil)
	conn, reader, response := dial()
	defer conn.Close()
	if response.StatusCode != 101 {
		t.Fatal("allowed WebSocket rejected", response.StatusCode)
	}
	id := <-opened
	setHostPolicy(t, p, "api", nil, []string{"0.0.0.0/0", "::/0"})
	tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: fixtureFrame(1, true, false, []byte("admitted"))}}})
	frame, err := fixtureReadFrame(reader, false)
	if err != nil || string(frame.payload) != "admitted" {
		t.Fatal("policy update interrupted open WebSocket", frame, err)
	}
	reconnect, _, denied := dial()
	reconnect.Close()
	if denied.StatusCode != 403 || len(opened) != 0 {
		t.Fatal("WebSocket reconnect retained old policy", denied.StatusCode)
	}
}

func TestIPPolicyTwoRelayHopHeadersAndCONNECT(t *testing.T) {
	for _, protocol := range []string{"http", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			p, tunnel, _, stream := meteringRelay(t, protocol == "tcp", "through two relays")
			p.config.NodeSecret, p.config.Insecure = "fixture-two-relay-secret", true
			tunnel.EndpointProtocol = protocol
			if protocol == "tcp" {
				tunnel.Capabilities[common.CapabilityConnectionStreamV1] = true
			}
			setHostPolicy(t, p, "", nil, []string{"198.51.100.0/24", "2001:db9::/32", "fe80::/10"})
			server := httptest.NewUnstartedServer(p.createHandler())
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			ingress := &ProxyServer{Domain: p.Domain, config: p.config, tunnelServer: NewTunnelServer(p.config, nil, nil, nil), tunnelCache: map[string]string{"api": strings.TrimPrefix(server.URL, "https://")}}
			authority := NewInternalServer(p.tunnelServer, strings.TrimPrefix(server.URL, "https://"), false)
			authority.proxy = p
			ingress.nodeClients = map[string]internalpb.InternalServiceClient{"publisher": forwardPermissionPeer{server: authority}}
			owner := relayJWT(t, p, "owner@example.com")
			for _, tt := range []struct {
				peer string
				want int
			}{{"198.51.100.1:1234", 403}, {"[2001:db9::1]:1234", 403}, {"[fe80::10%eth0]:1234", 403}, {"192.0.2.1:1234", 200}, {"[2001:db8::1]:1234", 200}} {
				r := httptest.NewRequest("GET", "https://api.tunn.test/", nil)
				r.RemoteAddr = tt.peer
				r.Header.Set("Authorization", "Bearer "+owner)
				r.Header.Set("Connection", "Tunn-Relay-For, Tunn-Relay-Proto, Tunn-Relay-Signature")
				r.Header.Set("X-Forwarded-For", "192.0.2.1")
				r.Header.Set(relayForwardedFor, "192.0.2.1")
				r.Header.Set(relayForwardedSignature, "forged")
				if protocol == "tcp" {
					r.Method = "CONNECT"
					r.URL.Path = common.TCPConnectPath
					r.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
				}
				stream.mu.Lock()
				before := len(stream.sentMsgs)
				stream.mu.Unlock()
				w := httptest.NewRecorder()
				ingress.createHandler().ServeHTTP(w, r)
				if w.Code != tt.want || tt.want == 200 && w.Body.String() != "through two relays" {
					t.Fatalf("%s peer=%s: %d %s", protocol, tt.peer, w.Code, w.Body)
				}
				stream.mu.Lock()
				count := len(stream.sentMsgs)
				stream.mu.Unlock()
				if tt.want == 403 && count != before {
					t.Fatal("blocked cross-relay request reached publisher")
				}
			}
		})
	}
}

func TestIPPolicyCLIOwnerAuthorizationJourney(t *testing.T) {
	p := durableFixture(t)
	device := durableLogin(t, p)
	code, err := p.storage.(storage.ScopedDeviceStorage).CreateDeviceCodeForPurpose(context.Background(), "management", "")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := p.storage.AuthorizeDeviceCode(context.Background(), code.Code, "owner@example.com"); !ok || err != nil {
		t.Fatal("owner browser authorization failed", err)
	}
	w := httptest.NewRecorder()
	p.handleDeviceToken(w, httptest.NewRequest("GET", "https://tunn.test/api/device/token?code="+url.QueryEscape(code.Code), nil))
	var owner durableTokenFixture
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &owner) != nil || owner.Access == "" || owner.Refresh != "" {
		t.Fatal("owner token exchange failed")
	}
	binary := os.Getenv("TUNN_TEST_BINARY")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "tunn")
		build := exec.Command("nice", "-n", "10", "make", "build", "BUILD_OUTPUT="+binary)
		build.Dir = "../.."
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build CLI fixture: %v %s", err, output)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "tunn.test"
		p.createHandler().ServeHTTP(w, r)
	}))
	defer server.Close()
	dir := t.TempDir()
	ownerFile, deviceFile := filepath.Join(dir, "owner.jwt"), filepath.Join(dir, "device.jwt")
	for name, token := range map[string]string{ownerFile: owner.Access, deviceFile: device.Access} {
		if err := os.WriteFile(name, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(file string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		args = append([]string{"ip-policy"}, args...)
		args = append(args, "--server", server.URL, "--owner-token-file", file)
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = append(os.Environ(), "TUNN_ENV=dev", "TUNN_CONFIG_DIR="+dir)
		return cmd.CombinedOutput()
	}
	for _, args := range [][]string{{"get", "--account"}, {"set", "--account", "--deny", "0.0.0.0/0,::/0"}, {"get", "tools"}, {"set", "tools", "--allow", "192.0.2.0/24"}, {"clear", "tools"}, {"clear", "--account"}} {
		if output, err := run(ownerFile, args...); err != nil {
			t.Fatalf("owner CLI %v: %v %s", args, err, output)
		}
	}
	for _, args := range [][]string{{"get", "--account"}, {"set", "--account", "--deny", "::/0"}, {"clear", "--account"}} {
		if output, err := run(deviceFile, args...); err == nil || !strings.Contains(string(output), "401") {
			t.Fatalf("publisher CLI managed policy: %v", args)
		}
	}
}

func TestIPPolicyTwoRelayCONNECTFullDuplex(t *testing.T) {
	p, tunnel, _, stream := meteringRelay(t, true, "")
	p.config.NodeSecret, p.config.Insecure = "fixture-duplex-relay-secret", false
	tunnel.EndpointProtocol = "tcp"
	tunnel.Capabilities[common.CapabilityConnectionStreamV1] = true
	setHostPolicy(t, p, "api", []string{"127.0.0.0/8"}, nil)
	stream.hook = func(msg *pb.TunnelMessage) error {
		if open := msg.GetConnectionOpen(); open != nil {
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true}}})
		}
		if data := msg.GetConnectionData(); data != nil {
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: data.ConnectionId, Data: data.Data}}})
		}
		if end := msg.GetConnectionHalfClose(); end != nil {
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: end.ConnectionId}}})
		}
		return nil
	}
	remote := httptest.NewUnstartedServer(p.createHandler())
	remote.EnableHTTP2 = true
	remote.StartTLS()
	defer remote.Close()
	ca := filepath.Join(t.TempDir(), "relay-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	p.config.InternalCACert = ca
	ingress := &ProxyServer{Domain: p.Domain, config: p.config, tunnelServer: NewTunnelServer(p.config, nil, nil, nil), tunnelCache: map[string]string{"api": strings.TrimPrefix(remote.URL, "https://")}}
	authority := NewInternalServer(p.tunnelServer, strings.TrimPrefix(remote.URL, "https://"), false)
	authority.proxy = p
	ingress.nodeClients = map[string]internalpb.InternalServiceClient{"publisher": forwardPermissionPeer{server: authority}}
	front := httptest.NewUnstartedServer(ingress.createHandler())
	front.EnableHTTP2 = true
	front.StartTLS()
	defer front.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	input, upload := io.Pipe()
	defer input.Close()
	defer upload.Close()
	r, _ := http.NewRequestWithContext(ctx, "CONNECT", front.URL, input)
	r.Host = "api.tunn.test"
	r.Header.Set("Authorization", "Bearer "+relayJWT(t, p, "owner@example.com"))
	r.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
	roots := x509.NewCertPool()
	roots.AddCert(front.Certificate())
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(r)
	if err != nil {
		t.Fatal("duplex CONNECT failed", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.ProtoMajor != 2 {
		t.Fatal("duplex CONNECT protocol", response.StatusCode, response.Proto)
	}
	for _, payload := range []string{"first", "second"} {
		if _, err := io.WriteString(upload, payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(response.Body, got); err != nil || string(got) != payload {
			t.Fatal("response waited for upload EOF or changed bytes", err)
		}
	}
	_ = upload.Close()
	if remaining, err := io.ReadAll(response.Body); err != nil || len(remaining) != 0 {
		t.Fatal("CONNECT half-close was lost", err)
	}
}

// Export handler-rendered fixture pages for local browser acceptance captures.
// No owner credentials or production identities are needed by the browser.
func TestIPPolicyRenderedPages(t *testing.T) {
	p, _, _, _ := webSharingFixture(t)
	setHostPolicy(t, p, "", []string{"192.0.2.0/24", "2001:db8::/32"}, []string{"192.0.2.42/32"})
	cookie := &http.Cookie{Name: authCookieName, Value: relayJWT(t, p, "owner@example.com")}
	for _, tt := range []struct{ name, path, want string }{
		{"account", "/account/ip-policy?saved=1", "Policy saved"},
		{"endpoint", "/account/ip-policy?endpoint=api", "inherits the account default"},
		{"docs", "/docs/ip-restrictions", "Owner API"},
	} {
		r := httptest.NewRequest("GET", "https://tunn.test"+tt.path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), tt.want) {
			t.Fatalf("%s: %d %s", tt.name, w.Code, w.Body)
		}
		if dir := os.Getenv("TUNN_IP_POLICY_SHOTS"); dir != "" {
			if err := os.WriteFile(filepath.Join(dir, tt.name+".html"), w.Body.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	w := policyOpen(p, "198.51.100.1:1234", "", "anonymous", nil)
	if w.Code != 403 || strings.Contains(w.Body.String(), "192.0.2.0") {
		t.Fatal("denial leaked policy", w)
	}
	if dir := os.Getenv("TUNN_IP_POLICY_SHOTS"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "denied.html"), w.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
