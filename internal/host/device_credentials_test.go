package host

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type durableTokenFixture struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Device  string `json:"device_id"`
	Expires int    `json:"expires_in"`
	Error   string `json:"error"`
}

func durableFixture(t *testing.T) *ProxyServer {
	t.Helper()
	f := newMCPOAuthFixture(t)
	var err error
	f.p.devices, err = newDeviceCredentialStore(f.p.mcpOAuth.db)
	if err != nil {
		t.Fatal(err)
	}
	return f.p
}
func durableLogin(t *testing.T, p *ProxyServer) durableTokenFixture {
	t.Helper()
	code, err := p.storage.CreateDeviceCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://tunn.test/api/device/token?durable=1&code="+url.QueryEscape(code.Code), nil)
	pending := httptest.NewRecorder()
	p.handleDeviceToken(pending, req)
	if !strings.Contains(pending.Body.String(), "authorization_pending") {
		t.Fatal(pending.Body.String())
	}
	if ok, err := p.storage.AuthorizeDeviceCode(context.Background(), code.Code, "owner@example.com"); !ok || err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.handleDeviceToken(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var token durableTokenFixture
	if err = json.Unmarshal(rec.Body.Bytes(), &token); err != nil || token.Refresh == "" || token.Device == "" || (token.Expires < 298 || token.Expires > 300) {
		t.Fatal(token, err)
	}
	second := httptest.NewRecorder()
	p.handleDeviceToken(second, req)
	if second.Code != 400 {
		t.Fatal("device code reused", second.Code)
	}
	return token
}
func durableRefresh(p *ProxyServer, secret, request string) (*httptest.ResponseRecorder, durableTokenFixture) {
	data, _ := json.Marshal(map[string]string{"refresh_token": secret, "request_id": request})
	req := httptest.NewRequest("POST", "https://tunn.test/api/device/refresh", strings.NewReader(string(data)))
	rec := httptest.NewRecorder()
	p.handleDeviceRefresh(rec, req)
	var token durableTokenFixture
	_ = json.Unmarshal(rec.Body.Bytes(), &token)
	return rec, token
}
func TestDurableRotationReuseRevocation(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	now := time.Now()
	p.now = func() time.Time { return now }
	rec, next := durableRefresh(p, token.Refresh, strings.Repeat("a", 43))
	if rec.Code != 200 || next.Refresh == token.Refresh {
		t.Fatal(rec.Code, rec.Body.String())
	}
	retry, recovered := durableRefresh(p, token.Refresh, strings.Repeat("a", 43))
	if retry.Code != 200 || recovered.Refresh != next.Refresh {
		t.Fatal("lost-response recovery failed")
	}
	now = now.Add(time.Minute)
	rec, newest := durableRefresh(p, next.Refresh, strings.Repeat("b", 43))
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	rec, _ = durableRefresh(p, token.Refresh, strings.Repeat("stolen", 8))
	if rec.Code != 401 {
		t.Fatal("old generation replay accepted")
	}
	rec, _ = durableRefresh(p, newest.Refresh, strings.Repeat("c", 43))
	if rec.Code != 401 {
		t.Fatal("reuse failed to revoke family")
	}
	// A random unknown secret cannot revoke another device.
	other := durableLogin(t, p)
	rec, _ = durableRefresh(p, "tunn_rt_"+strings.Repeat("x", 43), strings.Repeat("d", 43))
	if rec.Code != 401 {
		t.Fatal(rec.Code)
	}
	rec, _ = durableRefresh(p, other.Refresh, strings.Repeat("e", 43))
	if rec.Code != 200 {
		t.Fatal("unknown secret revoked unrelated device")
	}
	if _, err := newDeviceCredentialStore(p.devices.db); err != nil {
		t.Fatal("additive migration not idempotent", err)
	}
}
func TestDurableRetryWindowAndRestart(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	now := time.Now()
	p.now = func() time.Time { return now }
	rec, next := durableRefresh(p, token.Refresh, strings.Repeat("a", 43))
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	registry, err := newDeviceCredentialStore(p.devices.db)
	if err != nil {
		t.Fatal(err)
	}
	p.devices = registry
	now = now.Add(60 * time.Second)
	rec, _ = durableRefresh(p, token.Refresh, strings.Repeat("a", 43))
	if rec.Code != 401 {
		t.Fatal("retry past window accepted")
	}
	rec, _ = durableRefresh(p, next.Refresh, strings.Repeat("b", 43))
	if rec.Code != 401 {
		t.Fatal("expired recovery did not revoke")
	}
}
func TestDurableScopeExpiryAndLegacy(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	email, device, expiry, err := parseDeviceToken(token.Access, p.getJWTSigningKey(), time.Now())
	if err != nil || email != "owner@example.com" || device != token.Device {
		t.Fatal(err)
	}
	if _, _, _, err = parseDeviceToken(token.Access, p.getJWTSigningKey(), expiry); err == nil {
		t.Fatal("expired access accepted")
	}
	if _, err = p.tunnelServer.validateJWTAndExtractEmail(token.Access); err == nil {
		t.Fatal("device token accepted as management identity")
	}
	for _, tunnel := range []*TunnelConnection{{}, {TunnelID: "tools"}} {
		req := httptest.NewRequest("GET", "https://tools.tunn.test/", nil)
		req.Header.Set("Tunn-Authorization", "Bearer "+token.Access)
		_, _, _, ok := p.getAuthFromTunnelBearer(req, tunnel)
		if ok != (tunnel.TunnelID != "") {
			t.Fatal("device scope escaped tunnel boundary")
		}
	}
	// Reject the same device JWT on representative management routes.
	for _, path := range []string{"/api/ssh/keys", "/api/usage", "/api/endpoints/tools/grants", "/api/mcp/clients?tunnel=tools", "/api/reports"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://tunn.test"+path, nil)
		req.Header.Set("Authorization", "Bearer "+token.Access)
		p.createHandler().ServeHTTP(rec, req)
		if rec.Code == 200 {
			t.Fatal("device managed account via", path)
		}
	}
	code, err := p.storage.CreateDeviceCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.storage.AuthorizeDeviceCode(context.Background(), code.Code, "owner@example.com")
	rec := httptest.NewRecorder()
	p.handleDeviceToken(rec, httptest.NewRequest("GET", "https://tunn.test/api/device/token?code="+url.QueryEscape(code.Code), nil))
	var legacy durableTokenFixture
	_ = json.Unmarshal(rec.Body.Bytes(), &legacy)
	if legacy.Expires != 86400 || legacy.Refresh != "" {
		t.Fatal("legacy exchange changed")
	}
	if _, err = p.tunnelServer.validateJWTAndExtractEmail(legacy.Access); err != nil {
		t.Fatal("legacy access rejected", err)
	}
}
func TestDurableDeviceManagement(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	cookie := securityCookie(t, p, "owner@example.com")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://tunn.test/account/devices", nil)
	req.AddCookie(cookie)
	p.handleDevices(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), token.Device) || strings.Contains(rec.Body.String(), token.Refresh) {
		t.Fatal("device listing failed", rec.Code)
	}
	revoke := func(email, csrf string) int {
		req := httptest.NewRequest("POST", "https://tunn.test/account/devices", strings.NewReader(url.Values{"device_id": {token.Device}, "csrf_token": {csrf}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://tunn.test")
		req.AddCookie(securityCookie(t, p, email))
		rec := httptest.NewRecorder()
		p.handleDevices(rec, req)
		return rec.Code
	}
	if revoke("owner@example.com", "") != 403 {
		t.Fatal("revoke omitted CSRF")
	}
	// CSRF token is bound to the exact owner session cookie.
	req = httptest.NewRequest("GET", "https://tunn.test/account/devices", nil)
	req.AddCookie(cookie)
	csrf, err := p.createCSRFToken(req, "/account/devices")
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "https://tunn.test/account/devices", strings.NewReader(url.Values{"device_id": {token.Device}, "csrf_token": {csrf}}.Encode()))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://tunn.test")
	rec = httptest.NewRecorder()
	p.handleDevices(rec, req)
	if rec.Code != 303 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	rec, _ = durableRefresh(p, token.Refresh, strings.Repeat("a", 43))
	if rec.Code != 401 {
		t.Fatal("owner revocation failed")
	}
}

type durableControlStream struct {
	mockTunnelStream
	ctx      context.Context
	incoming chan *pb.TunnelMessage
	outgoing chan *pb.TunnelMessage
}

func (s *durableControlStream) Context() context.Context { return s.ctx }
func (s *durableControlStream) Recv() (*pb.TunnelMessage, error) {
	select {
	case m, ok := <-s.incoming:
		if !ok {
			return nil, io.EOF
		}
		return m, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *durableControlStream) Send(m *pb.TunnelMessage) error {
	select {
	case s.outgoing <- m:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func TestDurablePublisherSurvives48Hours(t *testing.T) {
	p := durableFixture(t)
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	clock := func() time.Time { return time.Unix(seconds.Load(), 0) }
	p.now = clock
	p.tunnelServer.now = clock
	token := durableLogin(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 2), outgoing: make(chan *pb.TunnelMessage, 4)}
	stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "forge-ssh", TargetUrl: "tcp", EndpointProtocol: "tcp", AuthToken: token.Access, TunnelKey: p.config.WellKnownKey, AllowedEmails: []string{"owner@example.com"}, Capabilities: []string{deviceReauthCapability, "connection-stream-v1"}}}}
	done := make(chan error, 1)
	go func() { done <- p.tunnelServer.EstablishTunnel(stream) }()
	select {
	case response := <-stream.outgoing:
		if !response.GetRegisterResponse().Success {
			t.Fatal(response)
		}
	case err := <-done:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("registration stalled")
	}
	tunnel, ok := p.tunnelServer.GetTunnel("forge-ssh")
	if !ok {
		t.Fatal("tunnel missing")
	}
	pending, err := tunnel.addPendingConnection("live-ssh")
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 720; step++ {
		seconds.Add(240)
		rec, next := durableRefresh(p, token.Refresh, fmt.Sprintf("%043d", step))
		if rec.Code != 200 {
			t.Fatal(step, rec.Body.String())
		}
		token = next
		stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{AuthToken: token.Access}}}
		stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: "live-ssh", Data: []byte("SSH bytes")}}}
		select {
		case event := <-pending.events:
			if string(event.data) != "SSH bytes" {
				t.Fatal("SSH stream changed")
			}
		case err := <-done:
			t.Fatal(step, err)
		case <-time.After(3 * time.Second):
			t.Fatal("SSH delivery stalled")
		}
		if current, ok := p.tunnelServer.GetTunnel("forge-ssh"); !ok || current != tunnel {
			t.Fatal("publisher restarted")
		}
		select {
		case <-pending.done:
			t.Fatal("live SSH dropped during renewal")
		default:
		}
	}
	// Revoked publisher cannot mint another token and loses its live lease.
	_, err = p.devices.db.Exec(`UPDATE durable_devices SET revoked=? WHERE id=?`, clock().Unix(), token.Device)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := durableRefresh(p, token.Refresh, strings.Repeat("z", 43))
	if rec.Code != 401 {
		t.Fatal("revoked publisher refreshed")
	}
	seconds.Add(301)
	select {
	case err := <-done:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expired lease remained online")
	}
	select {
	case <-pending.done:
	default:
		t.Fatal("revoked publisher retained SSH stream")
	}
	if _, ok = p.tunnelServer.GetTunnel("forge-ssh"); ok {
		t.Fatal("expired publisher remained registered")
	}
}
func TestDurableLeaseRejectsIdentitySwitch(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	email, device, expiry, err := parseDeviceToken(token.Access, p.getJWTSigningKey(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lease := &publisherDeviceLease{email: email, device: device, expiry: expiry}
	other := durableLogin(t, p)
	if lease.renew(other.Access, p.getJWTSigningKey(), time.Now()) == nil {
		t.Fatal("device switch accepted")
	}
	if lease.renew(token.Access, p.getJWTSigningKey(), expiry) == nil {
		t.Fatal("expired lease resurrected")
	}
	parsed, _, _ := jwt.NewParser().ParseUnverified(token.Access, jwt.MapClaims{})
	claims := parsed.Claims.(jwt.MapClaims)
	claims["scope"] = "publish connect manage"
	forged, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if lease.renew(forged, p.getJWTSigningKey(), time.Now()) == nil {
		t.Fatal("scope expansion accepted")
	}
}

func TestDurableLeaseExpiresWithBlockedSSHDelivery(t *testing.T) {
	p := durableFixture(t)
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	clock := func() time.Time { return time.Unix(seconds.Load(), 0) }
	p.now = clock
	p.tunnelServer.now = clock
	token := durableLogin(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 32), outgoing: make(chan *pb.TunnelMessage, 1)}
	stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "forge-ssh", TargetUrl: "tcp", EndpointProtocol: "tcp", AuthToken: token.Access, TunnelKey: p.config.WellKnownKey, AllowedEmails: []string{"owner@example.com"}, Capabilities: []string{deviceReauthCapability, "connection-stream-v1"}}}}
	done := make(chan error, 1)
	go func() { done <- p.tunnelServer.EstablishTunnel(stream) }()
	select {
	case response := <-stream.outgoing:
		if !response.GetRegisterResponse().Success {
			t.Fatal(response)
		}
	case err := <-done:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("registration stalled")
	}
	tunnel, _ := p.tunnelServer.GetTunnel("forge-ssh")
	pending, err := tunnel.addPendingConnection("blocked-ssh")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 17; i++ {
		stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: "blocked-ssh", Data: []byte("blocked")}}}
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(pending.events) != cap(pending.events) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(pending.events) != cap(pending.events) {
		t.Fatal("delivery did not block")
	}
	seconds.Add(301)
	select {
	case err := <-done:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked delivery prevented lease expiry")
	}
	select {
	case <-pending.done:
	default:
		t.Fatal("blocked SSH stream survived lease expiry")
	}
}

func TestDurableEndpointRelayClockSkew(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	request := httptest.NewRequest("GET", "https://tools.tunn.test/", nil)
	request.Header.Set("Tunn-Authorization", "Bearer "+token.Access)
	p.now = func() time.Time { return time.Now().Add(-30 * time.Second) }
	if _, _, _, ok := p.getAuthFromTunnelBearer(request, &TunnelConnection{TunnelID: "tools"}); !ok {
		t.Fatal("bounded relay clock skew rejected device access")
	}
	p.now = func() time.Time { return time.Now().Add(-2 * time.Minute) }
	if _, _, _, ok := p.getAuthFromTunnelBearer(request, &TunnelConnection{TunnelID: "tools"}); ok {
		t.Fatal("unbounded relay clock skew accepted")
	}
	// Signature validation and legacy iat validation still apply.
	p.now = nil
	claims := jwt.MapClaims{"type": "access", "email": "owner@example.com", "iat": time.Now().Add(time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	future, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	request.Header.Set("Tunn-Authorization", "Bearer "+future)
	if _, _, _, ok := p.getAuthFromTunnelBearer(request, &TunnelConnection{TunnelID: "tools"}); ok {
		t.Fatal("legacy issued-at validation bypassed")
	}
}
