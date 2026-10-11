package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/metering"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

func webSharingFixture(t *testing.T) (*ProxyServer, *TunnelConnection, *metering.Store, *meteringFixtureStream) {
	t.Helper()
	p, tunnel, ledger, stream := meteringRelay(t, false, "private app")
	p.config.PublicAddr = "tunn.test"
	tunnel.AllowedEmails = nil
	tunnel.EndpointProtocol = "http"
	out, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Mode: "private"})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.ResourceID = out.Resources[0].Id
	tunnel.ExposureMode = "private"
	p.tunnelServer.sharing = ledger
	return p, tunnel, ledger, stream
}
func sharingCall(t *testing.T, p *ProxyServer, method, endpoint, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "https://tunn.test/api/sharing/"+endpoint, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}
func webOpen(t *testing.T, p *ProxyServer, email string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "https://api.tunn.test/", nil)
	if email != "" {
		r.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, p, email)})
	}
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}
func TestWebSharingPrivateDefaultLiveAdmissionAndAudit(t *testing.T) {
	p, tunnel, ledger, _ := webSharingFixture(t)
	owner := relayJWT(t, p, "owner@example.com")
	if w := webOpen(t, p, ""); w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "/auth/login") {
		t.Fatal(w)
	}
	if w := webOpen(t, p, "owner@example.com"); w.Code != 200 {
		t.Fatal(w)
	}
	for _, email := range []string{"alice@example.com", "stranger@example.com"} {
		if w := webOpen(t, p, email); w.Code != 403 {
			t.Fatalf("non-granted %s=%d", email, w.Code)
		}
	}
	start := time.Now()
	if w := sharingCall(t, p, "POST", "api", owner, `{"email":"Alice@example.com"}`); w.Code != 200 {
		t.Fatal(w)
	}
	if w := webOpen(t, p, "alice@example.com"); w.Code != 200 {
		t.Fatal(w)
	}
	t.Logf("scripted share-to-recipient-in: %s", time.Since(start))
	if w := webOpen(t, p, "stranger@example.com"); w.Code != 403 {
		t.Fatal("sharing link transferred authority")
	}
	for _, token := range []string{"", p.config.NodeSecret, "garbage", relayJWT(t, p, "stranger@example.com"), relayJWT(t, p, "alice@example.com")} {
		if w := sharingCall(t, p, "POST", "api", token, `{"email":"evil@example.com"}`); w.Code == 200 {
			t.Fatal("non-owner changed permission")
		}
	}
	_, grantToken := relayGrant(t, ledger, 10, 10000)
	if w := sharingCall(t, p, "GET", "api", grantToken, ""); w.Code != 401 {
		t.Fatal("consumer grant became owner")
	}
	r := httptest.NewRequest("POST", "https://tunn.test/api/sharing/api", strings.NewReader(`{"email":"evil@example.com"}`))
	r.Header.Set("Authorization", "Bearer "+owner)
	r.Header.Set("Origin", "https://api.tunn.test")
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("publisher origin changed permission")
	}
	start = time.Now()
	if w := sharingCall(t, p, "DELETE", "api", owner, `{"email":"alice@example.com"}`); w.Code != 200 {
		t.Fatal(w)
	}
	if w := webOpen(t, p, "alice@example.com"); w.Code != 403 {
		t.Fatal("revoked cookie retained access")
	}
	t.Logf("revoke-to-next-request-denied: %s", time.Since(start))
	expires := time.Now().Add(20 * time.Millisecond).UnixMilli()
	body, _ := json.Marshal(map[string]any{"email": "alice@example.com", "expires_at": expires})
	if w := sharingCall(t, p, "POST", "api", owner, string(body)); w.Code != 200 {
		t.Fatal(w)
	}
	time.Sleep(30 * time.Millisecond)
	if w := webOpen(t, p, "alice@example.com"); w.Code != 403 {
		t.Fatal("expired person admitted")
	}
	events := relayExport(t, ledger)
	allowed, denied := false, false
	for _, e := range events.Events {
		if e.Caller == "email:alice@example.com" {
			if e.Allowed {
				allowed = true
			} else {
				denied = true
			}
		}
	}
	if !allowed || !denied {
		t.Fatalf("missing identity and decision audit: %v", events.Events)
	}
	// Explicit public restores anonymous access; immutable-generation checks remain.
	_, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: "api", Mode: "public"})
	if err != nil {
		t.Fatal(err)
	}
	if w := webOpen(t, p, ""); w.Code != 200 {
		t.Fatal("explicit public denied")
	}
	_, err = ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: "another-owner", Endpoint: "api", Mode: "private"})
	if err != nil {
		t.Fatal(err)
	}
	if w := webOpen(t, p, "owner@example.com"); w.Code == 200 {
		t.Fatal("old generation forwarded after ownership change")
	}
}
func TestWebSharingCookieDashboardCSRFAndPeople(t *testing.T) {
	p, _, ledger, _ := webSharingFixture(t)
	machineGrant, _ := relayGrant(t, ledger, 10, 10000)
	get := httptest.NewRequest("GET", "https://tunn.test/account/sharing?tunnel=api", nil)
	get.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, p, "owner@example.com")})
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, get)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Copy link") || !strings.Contains(w.Body.String(), "People who can open") {
		t.Fatal(w)
	}
	if !strings.Contains(w.Body.String(), machineGrant.Id) || !strings.Contains(w.Body.String(), "Machine access") {
		t.Fatal("machine access hidden from owner")
	}
	token := hiddenMCPField(t, w.Body.String(), "csrf_token")
	for _, valid := range []bool{false, true} {
		form := url.Values{"email": {"alice@example.com"}, "action": {"share"}}
		if valid {
			form.Set("csrf_token", token)
		}
		r := httptest.NewRequest("POST", get.URL.String(), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://tunn.test")
		r.AddCookie(get.Cookies()[0])
		w = httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		want := 403
		if valid {
			want = 303
		}
		if w.Code != want {
			t.Fatalf("csrf %v: %d %s", valid, w.Code, w.Body.String())
		}
	}
	w = httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, get)
	if !strings.Contains(w.Body.String(), "alice@example.com") || !strings.Contains(w.Body.String(), "Remove access") {
		t.Fatal("people not shown")
	}
	if w := webOpen(t, p, "alice@example.com"); w.Code != 200 {
		t.Fatal("UI permission did not admit")
	}
}
func TestWebSharingRevokesIdleHTTPStream(t *testing.T) {
	p, tunnel, _, stream := webSharingFixture(t)
	owner := relayJWT(t, p, "owner@example.com")
	if w := sharingCall(t, p, "POST", "api", owner, `{"email":"alice@example.com"}`); w.Code != 200 {
		t.Fatal(w)
	}
	tunnel.Capabilities = map[string]bool{common.CapabilityConnectionStreamV1: true, common.CapabilityHTTPStreamV1: true}
	tunnel.pendingStreams = make(map[string]*pendingConnection)
	stream.hook = func(msg *pb.TunnelMessage) error {
		if half := msg.GetConnectionHalfClose(); half != nil {
			id := half.ConnectionId
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/event-stream"}}}}})
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte("data: ready\n\n")}}})
		}
		return nil
	}
	server := httptest.NewServer(p.createHandler())
	defer server.Close()
	h := server.Client()
	h.Timeout = 6 * time.Second
	req, _ := http.NewRequest("GET", server.URL+"/events", nil)
	req.Host = "api.tunn.test"
	req.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, p, "alice@example.com")})
	resp, err := h.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	ready := make([]byte, len("data: ready\n\n"))
	if _, err = io.ReadFull(resp.Body, ready); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if w := sharingCall(t, p, "DELETE", "api", owner, `{"email":"alice@example.com"}`); w.Code != 200 {
		t.Fatal(w)
	}
	if _, err = io.ReadAll(resp.Body); err == nil {
		t.Fatal("revoked stream completed successfully")
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("revoke exceeded five seconds: %s", elapsed)
	} else {
		t.Logf("revoke-to-idle-stream-cutoff: %s", elapsed)
	}
}

func TestWebSharingVersionedAndLegacyRegistration(t *testing.T) {
	for _, tc := range []struct {
		name      string
		version   uint32
		mode      string
		allow     []string
		authority bool
		want      bool
		exposure  string
	}{
		{"private-default", 1, "private", nil, true, true, "private"},
		{"explicit-public", 1, "public", nil, true, true, "public"},
		{"legacy-empty", 0, "", nil, true, true, "legacy-public"},
		{"legacy-allow", 0, "", []string{"alice@example.com"}, true, true, "private"},
		{"missing-authority", 1, "private", nil, false, false, ""},
		{"future-version", 2, "private", nil, true, false, ""},
		{"missing-mode", 1, "", nil, true, false, ""},
		{"public-and-allow", 1, "public", []string{"alice@example.com"}, true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			s := f.p.tunnelServer
			account, err := s.storage.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if tc.authority {
				s.sharing = f.p.meter.(metering.SharingBackend)
			}
			stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
			var registered *TunnelConnection
			stream.onSend = func(msg *pb.TunnelMessage) error {
				if res := msg.GetRegisterResponse(); res != nil && res.Success {
					registered, _ = s.GetTunnel("preview")
				}
				return stream.mockTunnelStream.Send(msg)
			}
			stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "preview", TargetUrl: "http", AuthToken: createTestJWT("owner@example.com", s.cfg.JWTSecret), TunnelKey: s.cfg.WellKnownKey, CreatorEmail: "forged@example.com", AllowedEmails: tc.allow, ExposureVersion: tc.version, ExposureMode: tc.mode}}}
			close(stream.recvQueue)
			_ = s.EstablishTunnel(stream)
			if len(stream.sentMsgs) == 0 || stream.sentMsgs[0].GetRegisterResponse().Success != tc.want {
				t.Fatalf("registration: %v", stream.sentMsgs)
			}
			if tc.want {
				if registered == nil || registered.ExposureMode != tc.exposure || registered.AccountID != account.ID || registered.CreatorEmail != "owner@example.com" || registered.ResourceID == "" {
					t.Fatalf("wrong exposure or owner: %+v", registered)
				}
			}
		})
	}
}

type unavailableSharing struct{ metering.Backend }

func (u unavailableSharing) Sharing(context.Context, *mp.SharingRequest) (*mp.SharingResponse, error) {
	return nil, fmt.Errorf("authority offline")
}
func TestWebSharingFailClosedWatchAndEmailBuckets(t *testing.T) {
	p, tunnel, ledger, _ := webSharingFixture(t)
	expires := time.Now().Add(250 * time.Millisecond).UnixMilli()
	out, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: tunnel.AccountID, Endpoint: "api", Email: "alice@example.com", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	resource := out.Resources[0]
	if !webPersonAllowed(resource, []string{"other@example.com", "alice@example.com"}, tunnel.CreatorEmail, time.Now()) || webPersonAllowed(resource, []string{"stranger@example.com"}, tunnel.CreatorEmail, time.Now()) {
		t.Fatal("email bucket permission failed")
	}
	for _, outage := range []bool{false, true} {
		if outage {
			p.meter = unavailableSharing{ledger}
		}
		r := httptest.NewRequest("GET", "https://api.tunn.test/events", nil)
		watched, stop := p.watchWebPermission(r, tunnel, []string{"alice@example.com"}, false)
		select {
		case <-watched.Context().Done():
		case <-time.After(5 * time.Second):
			t.Fatal("idle request exceeded watch bound")
		}
		stop()
		var reason *webPermissionError
		if !errors.As(context.Cause(watched.Context()), &reason) {
			t.Fatal("watch lost revocation audit cause")
		}
	}
	if w := webOpen(t, p, "owner@example.com"); w.Code != 503 {
		t.Fatal("authority outage admitted owner")
	}
}

func TestWebSharingRealPublisherAndWebSocketRevocation(t *testing.T) {
	f := newMCPOAuthFixture(t)
	p := f.p
	p.tunnelServer.sharing = p.meter.(metering.SharingBackend)
	fixture := &webSocketFixture{closes: make(chan []byte, 16)}
	origin := httptest.NewServer(fixture)
	defer origin.Close()
	gs := grpc.NewServer()
	pb.RegisterTunnelServiceServer(gs, p.tunnelServer)
	p.grpcServer = gs
	relay := httptest.NewUnstartedServer(p.createHTTP2Router(p.createHandler()))
	relay.EnableHTTP2 = true
	relay.StartTLS()
	defer relay.Close()
	defer gs.Stop()
	// The HTTP2 router dispatches public gRPC using p.grpcServer.
	p.grpcServer = gs
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	publisher := &client.ServeClient{TunnelID: "websocket-fixture", TargetURL: origin.URL, ServerAddr: relay.Listener.Addr().String(), AuthToken: relayJWT(t, p, "owner@example.com"), TunnelKey: p.config.WellKnownKey, RequireSharing: true, Insecure: true, Quiet: true, OnRegistered: func(u string) { ready <- u }}
	started := time.Now()
	go func() { done <- publisher.Run(ctx) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("private publisher did not register")
	}
	tunnel, _ := p.tunnelServer.GetTunnel(publisher.TunnelID)
	if tunnel == nil || tunnel.ResourceID == "" || tunnel.ExposureMode != "private" {
		t.Fatal("publisher lost private exposure")
	}
	h := relay.Client()
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	open := func(email string) int {
		t.Helper()
		req, _ := http.NewRequest("GET", relay.URL+"/http", nil)
		req.Host = "websocket-fixture.tunn.test"
		if email != "" {
			req.AddCookie(securityCookie(t, p, email))
		}
		resp, err := h.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if open("") != 302 || open("owner@example.com") != 200 || open("alice@example.com") != 403 {
		t.Fatal("real publisher was not owner-only")
	}
	owner := relayJWT(t, p, "owner@example.com")
	if w := sharingCall(t, p, "POST", publisher.TunnelID, owner, `{"email":"alice@example.com"}`); w.Code != 200 {
		t.Fatal(w)
	}
	if open("alice@example.com") != 200 {
		t.Fatal("share did not reach actual origin")
	}
	t.Logf("scripted publish-to-recipient-in: %s", time.Since(started))
	stack := &webSocketStack{relay: relay, proxy: p, fixture: fixture}
	socket, reader := mustWebSocket(t, stack, "/echo", http.Header{"Cookie": {stack.cookie(t, "alice@example.com")}})
	defer socket.Close()
	_, err := socket.Write(fixtureFrame(1, true, true, []byte("private echo")))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := fixtureReadFrame(reader, false)
	if err != nil || string(frame.payload) != "private echo" {
		t.Fatalf("private websocket echo: %q %v", frame.payload, err)
	}
	started = time.Now()
	if w := sharingCall(t, p, "DELETE", publisher.TunnelID, owner, `{"email":"alice@example.com"}`); w.Code != 200 {
		t.Fatal(w)
	}
	socket.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = fixtureReadFrame(reader, false)
	if err == nil {
		t.Fatal("revoked websocket delivered another frame")
	}
	if elapsed := time.Since(started); elapsed >= 5*time.Second {
		t.Fatalf("websocket revoke exceeded bound: %s", elapsed)
	} else {
		t.Logf("revoke-to-idle-websocket-cutoff: %s", elapsed)
	}
	if open("alice@example.com") != 403 {
		t.Fatal("revoked websocket user could reopen")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not stop")
	}
}

func TestWebSharingAnonymousStreamLosesPublicExposure(t *testing.T) {
	p, tunnel, ledger, _ := webSharingFixture(t)
	_, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: "api", Mode: "public"})
	if err != nil {
		t.Fatal(err)
	}
	watched, stop := p.watchWebPermission(httptest.NewRequest("GET", "https://api.tunn.test/", nil), tunnel, nil, true)
	defer stop()
	_, err = ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: "api", Mode: "private"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-watched.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("anonymous stream kept private access")
	}
}

func TestWebSharingSelfHostedPublicRequiresExplicitChoice(t *testing.T) {
	for _, mode := range []string{"private", "public"} {
		cfg := testConfig()
		cfg.ClientSecret = "operator-secret"
		s := NewTunnelServer(cfg, nil, nil, nil)
		stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
		stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "preview", TargetUrl: "http", AuthToken: cfg.ClientSecret, ExposureVersion: 1, ExposureMode: mode}}}
		close(stream.recvQueue)
		_ = s.EstablishTunnel(stream)
		if len(stream.sentMsgs) == 0 || stream.sentMsgs[0].GetRegisterResponse().Success != (mode == "public") {
			t.Fatalf("accountless %s registration: %v", mode, stream.sentMsgs)
		}
	}
}
