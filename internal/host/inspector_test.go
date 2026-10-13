package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/identity"
	"github.com/ehrlich-b/tunn/internal/inspection"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
)

type webInspectorFixture struct {
	p          *ProxyServer
	tunnel     *TunnelConnection
	stream     *meteringFixtureStream
	local      *storage.LocalStorage
	db         *sql.DB
	cookie     *http.Cookie
	csrf       string
	deliveries []*pb.HttpRequest
}

func newWebInspectorFixture(t *testing.T, requests, bytes int64) *webInspectorFixture {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	local := storage.NewLocalStorage(db)
	owner, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := metering.New(db, metering.WithAccountPlans(), metering.WithOwnerBudgets(requests, bytes))
	if err != nil {
		t.Fatal(err)
	}
	p := securityProxy(local)
	p.meter, p.planMeter = ledger, true
	p.config.PublicAddr = "tunn.test"
	stream := &meteringFixtureStream{}
	tunnel := &TunnelConnection{TunnelID: "api", TargetURL: "http", AccountID: owner.ID, CreatorEmail: owner.PrimaryEmail, AllowedEmails: []string{owner.PrimaryEmail, "alice@example.com"}, Stream: stream, Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityHTTPOriginReplayV1: true}, pendingRequests: make(map[string]chan *pb.HttpResponse)}
	p.tunnelServer.tunnels[tunnel.TunnelID] = tunnel
	f := &webInspectorFixture{p: p, tunnel: tunnel, stream: stream, local: local, db: db}
	incoming := map[string]*pb.HttpRequest{}
	stream.hook = func(message *pb.TunnelMessage) error {
		if open := message.GetConnectionOpen(); open != nil {
			incoming[open.ConnectionId] = &pb.HttpRequest{ConnectionId: open.ConnectionId, Method: open.HttpRequest.Method, Path: open.HttpRequest.Path, Headers: open.HttpRequest.Headers}
		}
		if data := message.GetConnectionData(); data != nil {
			incoming[data.ConnectionId].Body = append(incoming[data.ConnectionId].Body, data.Data...)
		}
		if end := message.GetConnectionHalfClose(); end != nil {
			f.deliveries = append(f.deliveries, incoming[end.ConnectionId])
			delete(incoming, end.ConnectionId)
			webInspectorStreamReply(tunnel, end.ConnectionId, 202, "RESPONSE_PAYLOAD_SENTINEL")
		}
		return nil
	}
	f.cookie = f.accountCookie(t, "owner@example.com")
	r := httptest.NewRequest("GET", "https://tunn.test/account/inspect", nil)
	r.AddCookie(f.cookie)
	f.csrf, err = p.createCSRFToken(r, inspectorCSRFAction)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *webInspectorFixture) accountCookie(t *testing.T, email string) *http.Cookie {
	t.Helper()
	account, err := f.local.FindOrCreateByEmails(context.Background(), []string{email}, "github")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err = f.p.setAccountCookie(w, account, email, "github"); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies()[0]
}
func (f *webInspectorFixture) call(method, path string, value any, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	var body io.Reader
	if value != nil {
		data, _ := json.Marshal(value)
		body = strings.NewReader(string(data))
	}
	r := httptest.NewRequest(method, "https://tunn.test"+path, body)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://tunn.test")
		r.Header.Set("X-Tunn-CSRF", f.csrf)
	}
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	return w
}
func (f *webInspectorFixture) seed(t *testing.T) inspection.Event {
	t.Helper()
	r := httptest.NewRequest("POST", "https://api.tunn.test/hooks?token=QUERY_SENTINEL", strings.NewReader("BODY_PAYLOAD_SENTINEL"))
	r.AddCookie(f.cookie)
	r.Header.Add("Cookie", "app_sid=COOKIE_SENTINEL")
	r.Header.Set("Authorization", "Bearer HEADER_SENTINEL")
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	if w.Code != 202 {
		t.Fatalf("delivery status=%d %s", w.Code, w.Body)
	}
	events := f.tunnel.inspectionHistory().Snapshot()
	if len(events) == 0 {
		t.Fatal("no terminal capture")
	}
	return events[len(events)-1]
}
func (f *webInspectorFixture) prepare(t *testing.T, event inspection.Event) string {
	t.Helper()
	w := f.call("POST", fmt.Sprintf("/api/inspector/api/requests/%d/prepare", event.ID), map[string]any{"session": f.tunnel.inspectionHistory().Session()}, f.cookie, nil)
	if w.Code != 200 {
		t.Fatalf("prepare=%d %s", w.Code, w.Body)
	}
	var out struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Action
}
func (f *webInspectorFixture) replayInput(event inspection.Event, action string) map[string]any {
	body := []byte("BODY_PAYLOAD_SENTINEL")
	headers := map[string]string{}
	for key, value := range event.Headers {
		headers[key] = value
	}
	headers["Authorization"] = "Bearer HEADER_SENTINEL"
	headers["Cookie"] = "app_sid=COOKIE_SENTINEL"
	return map[string]any{"session": f.tunnel.inspectionHistory().Session(), "action": action, "confirmed": true, "path": "/hooks?token=QUERY_SENTINEL", "headers": headers, "body": body}
}
func TestWebInspectorOwnerIsolationAndRedaction(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	event := f.seed(t)
	for _, path := range []string{"/api/inspector/endpoints", "/api/inspector/api/requests", fmt.Sprintf("/api/inspector/api/requests/%d", event.ID), "/account/inspect"} {
		w := f.call("GET", path, nil, f.cookie, nil)
		if w.Code != 200 {
			t.Fatalf("owner %s=%d %s", path, w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("private response was cacheable")
		}
		for _, sentinel := range []string{"QUERY_SENTINEL", "HEADER_SENTINEL", "COOKIE_SENTINEL", "BODY_PAYLOAD_SENTINEL", "RESPONSE_PAYLOAD_SENTINEL"} {
			if strings.Contains(w.Body.String(), sentinel) {
				t.Fatalf("%s leaked %s", path, sentinel)
			}
		}
		for _, email := range []string{"alice@example.com", "stranger@example.com"} {
			other := f.accountCookie(t, email)
			denied := f.call("GET", path, nil, other, nil)
			if path != "/account/inspect" && path != "/api/inspector/endpoints" && denied.Code != 403 {
				t.Fatalf("shared/wrong owner=%d", denied.Code)
			}
			if strings.Contains(denied.Body.String(), "/hooks") {
				t.Fatal("request metadata leaked to another owner")
			}
		}
		denied := f.call("GET", path, nil, nil, nil)
		if denied.Code != 401 {
			t.Fatalf("anonymous=%d", denied.Code)
		}
		denied = f.call("GET", path, nil, nil, map[string]string{"Authorization": "Bearer tunn_ep_fixture"})
		if denied.Code != 401 {
			t.Fatalf("endpoint token=%d", denied.Code)
		}
	}
	// A signed cookie cannot change accounts merely by changing its email.
	other := f.accountCookie(t, "stranger@example.com")
	_ = other
	w := httptest.NewRecorder()
	_ = f.p.signedSession(w, jwt.MapClaims{"account_id": f.tunnel.AccountID, "email": "stranger@example.com", "provider": "github", "email_verified": true}, authCookieName, "", time.Hour)
	if denied := f.call("GET", "/api/inspector/api/requests", nil, w.Result().Cookies()[0], nil); denied.Code != 403 {
		t.Fatal("UUID/email mismatch accepted")
	}
}
func TestWebInspectorReplayConfirmationAndIngress(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	event := f.seed(t)
	action := f.prepare(t, event)
	input := f.replayInput(event, action)
	path := fmt.Sprintf("/api/inspector/api/requests/%d/replay", event.ID)
	input["confirmed"] = false
	if w := f.call("POST", path, input, f.cookie, nil); w.Code != 400 {
		t.Fatalf("missing confirm=%d", w.Code)
	}
	input["confirmed"] = true
	for _, headers := range []map[string]string{{"X-Tunn-CSRF": ""}, {"Origin": "https://api.tunn.test"}, {"Origin": "https://tunn.test:444"}, {"Origin": ""}, {"Content-Type": "text/plain"}} {
		w := f.call("POST", path, input, f.cookie, headers)
		if w.Code != 403 && w.Code != 415 {
			t.Fatalf("invalid origin/CSRF/type=%d", w.Code)
		}
	}
	if w := f.call("GET", path, nil, f.cookie, nil); w.Code != 405 {
		t.Fatalf("GET replay=%d", w.Code)
	}
	before := len(f.deliveries)
	input["body"] = []byte("wrong")
	if w := f.call("POST", path, input, f.cookie, nil); w.Code != 409 || len(f.deliveries) != before {
		t.Fatal("mismatched body dispatched")
	}
	input["body"] = []byte("BODY_PAYLOAD_SENTINEL")
	result := f.call("POST", path, input, f.cookie, nil)
	if result.Code != 200 {
		t.Fatalf("replay=%d %s", result.Code, result.Body)
	}
	if len(f.deliveries) != before+1 {
		t.Fatal("replay delivery count")
	}
	req := f.deliveries[len(f.deliveries)-1]
	if req.Path != "/hooks?token=QUERY_SENTINEL" || string(req.Body) != "BODY_PAYLOAD_SENTINEL" || req.Headers["Authorization"] != "Bearer HEADER_SENTINEL" || req.Headers["Cookie"] != "app_sid=COOKIE_SENTINEL" {
		t.Fatal("reconstruction changed upstream request")
	}
	if strings.Contains(req.Headers["Cookie"], f.cookie.Value) || req.Headers["Tunn-Authorization"] != "" {
		t.Fatal("platform credential reached origin")
	}
	var out struct {
		Event inspection.Event `json:"event"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Event.ReplayOf != event.ID || out.Event.Status != 202 || out.Event.TerminalReason != "complete" || len(out.Event.Body) != 0 {
		t.Fatalf("invalid replay result: %+v", out.Event)
	}
	if w := f.call("POST", path, input, f.cookie, nil); w.Code != 409 || len(f.deliveries) != before+1 {
		t.Fatal("duplicate replay dispatched")
	}
	exported, err := f.p.meter.Export(context.Background(), &meterpb.ExportRequest{Owner: f.tunnel.AccountID, Endpoint: "api", Month: time.Now().UTC().Format("2006-01")})
	if err != nil {
		t.Fatal(err)
	}
	if exported.OwnerUsage.AdmittedRequests != 2 {
		t.Fatal("replay bypassed ingress accounting")
	}
}
func TestWebInspectorReplayQuotaAndSuspension(t *testing.T) {
	for _, scenario := range []string{"requests", "bytes", "suspended"} {
		t.Run(scenario, func(t *testing.T) {
			requests, bytes := int64(0), int64(0)
			if scenario == "requests" {
				requests = 1
			}
			if scenario == "bytes" {
				bytes = int64(len("BODY_PAYLOAD_SENTINEL") + len("RESPONSE_PAYLOAD_SENTINEL"))
			}
			f := newWebInspectorFixture(t, requests, bytes)
			event := f.seed(t)
			action := f.prepare(t, event)
			if scenario == "suspended" {
				if _, err := f.db.Exec("INSERT INTO ops_account_state(account_id,state,version,reason,actor,changed_at) VALUES(?,'suspended',1,'fixture','fixture','2026-10-12T00:00:00Z')", f.tunnel.AccountID); err != nil {
					t.Fatal(err)
				}
			}
			before := len(f.deliveries)
			w := f.call("POST", fmt.Sprintf("/api/inspector/api/requests/%d/replay", event.ID), f.replayInput(event, action), f.cookie, nil)
			expected := 429
			if scenario == "suspended" {
				expected = 403
			}
			if w.Code != expected || len(f.deliveries) != before {
				t.Fatalf("%s replay=%d %s deliveries=%d", scenario, w.Code, w.Body, len(f.deliveries))
			}
		})
	}
}
func TestWebInspectorReconnectExpiryAndBounds(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	event := f.seed(t)
	action := f.prepare(t, event)
	oldInput := f.replayInput(event, action)
	f.p.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	path := fmt.Sprintf("/api/inspector/api/requests/%d/replay", event.ID)
	if w := f.call("POST", path, oldInput, f.cookie, nil); w.Code != 409 {
		t.Fatal("expired action accepted")
	}
	f.p.now = nil
	old := f.tunnel
	replacement := &TunnelConnection{TunnelID: "api", TargetURL: "http", AccountID: old.AccountID, CreatorEmail: old.CreatorEmail, AllowedEmails: old.AllowedEmails, Stream: f.stream, Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityHTTPOriginReplayV1: true}, pendingRequests: make(map[string]chan *pb.HttpResponse)}
	f.p.tunnelServer.tunnels["api"] = replacement
	f.tunnel = replacement
	// Give the replacement the same numeric event ID, with a fresh session.
	replacement.inspectionHistory().Begin("new", "GET", "/", map[string]string{"Host": "api.tunn.test"}, 0, 0).Finish(200, "text/plain", "complete")
	if w := f.call("POST", path, oldInput, f.cookie, nil); w.Code != 409 {
		t.Fatal("old action crossed publisher replacement")
	}
	delete(f.p.tunnelServer.tunnels, "api")
	if w := f.call("GET", "/api/inspector/api/requests", nil, f.cookie, nil); w.Code != 503 {
		t.Fatal("offline history retained")
	}
	f.p.tunnelServer.tunnels["api"] = replacement
	for _, raw := range []string{`{"session":"x","unknown":true}`, `{"session":"x"} {}`, strings.Repeat(" ", inspection.ReplayInputLimit+1)} {
		r := httptest.NewRequest("POST", "https://tunn.test/api/inspector/api/requests/1/prepare", strings.NewReader(raw))
		r.AddCookie(f.cookie)
		r.Header.Set("Origin", "https://tunn.test")
		r.Header.Set("X-Tunn-CSRF", f.csrf)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("invalid bounded JSON=%d", w.Code)
		}
	}
}

func TestWebInspectorCrossNodeOriginalIngressAndReplay(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	resources, err := f.p.sharingBackend().Sharing(context.Background(), &meterpb.SharingRequest{Operation: "register", Owner: f.tunnel.AccountID, Endpoint: "api", Mode: "private"})
	if err != nil {
		t.Fatal(err)
	}
	f.tunnel.ResourceID = resources.Resources[0].Id
	remote := httptest.NewTLSServer(f.p.createHandler())
	defer remote.Close()
	addr := strings.TrimPrefix(remote.URL, "https://")
	edge := securityProxy(securityReplicaStorage(t, f.local))
	edge.meter = f.p.meter
	edge.planMeter = true
	edge.config.Insecure = true // Disposable TLS fixture certificate only.
	edge.nodeClients = map[string]internalpb.InternalServiceClient{"peer": mcpOAuthPeerClient{server: NewInternalServer(f.p.tunnelServer, addr, false)}}
	edge.config.NodeSecret = "fixture-cluster"
	f.p.config.NodeSecret = edge.config.NodeSecret
	ingress := httptest.NewRequest("POST", "https://api.tunn.test/hooks?token=QUERY_SENTINEL", strings.NewReader("BODY_PAYLOAD_SENTINEL"))
	ingress.AddCookie(f.cookie)
	ingress.Header.Add("Cookie", "app_sid=COOKIE_SENTINEL")
	ingress.Header.Set("Authorization", "Bearer HEADER_SENTINEL")
	ingress.Header.Set("Content-Type", "text/plain")
	ingress.Header.Set("Forwarded", "for=FORGED_SENTINEL")
	ingress.Header.Set("X-Forwarded-For", "FORGED_SENTINEL")
	delivery := httptest.NewRecorder()
	edge.createHandler().ServeHTTP(delivery, ingress)
	if delivery.Code != 202 {
		t.Fatalf("cross-node original ingress=%d %s", delivery.Code, delivery.Body)
	}
	event := f.tunnel.inspectionHistory().Snapshot()[0]
	for name := range event.Headers {
		lower := strings.ToLower(name)
		if lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "tunn-relay-") {
			t.Fatalf("retained relay-only field %s", name)
		}
	}
	remoteCall := func(method, path string, input any, cookie *http.Cookie) *httptest.ResponseRecorder {
		var body io.Reader
		if input != nil {
			data, _ := json.Marshal(input)
			body = strings.NewReader(string(data))
		}
		r := httptest.NewRequest(method, "https://tunn.test"+path, body)
		r.AddCookie(cookie)
		if method == "POST" {
			r.Header.Set("Origin", "https://tunn.test")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Tunn-CSRF", f.csrf)
		}
		w := httptest.NewRecorder()
		edge.createHandler().ServeHTTP(w, r)
		return w
	}
	if w := remoteCall("GET", "/api/inspector/endpoints", nil, f.cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "api") {
		t.Fatalf("cross-node endpoints=%d %s", w.Code, w.Body)
	}
	if w := remoteCall("GET", "/api/inspector/api/requests", nil, f.cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "/hooks") {
		t.Fatalf("cross-node history=%d %s", w.Code, w.Body)
	}
	stranger := f.accountCookie(t, "stranger@example.com")
	if w := remoteCall("GET", "/api/inspector/api/requests", nil, stranger); w.Code != 403 {
		t.Fatalf("remote owner isolation=%d", w.Code)
	}
	action := f.prepare(t, event)
	before := len(f.deliveries)
	if w := remoteCall("POST", fmt.Sprintf("/api/inspector/api/requests/%d/replay", event.ID), f.replayInput(event, action), f.cookie); w.Code != 200 || len(f.deliveries) != before+1 {
		t.Fatalf("cross-node replay=%d %s", w.Code, w.Body)
	}
	// A stale cache routes once, and the remote node must not loop back.
	edge.tunnelCache["api"] = addr
	delete(f.p.tunnelServer.tunnels, "api")
	if w := remoteCall("GET", "/api/inspector/api/requests", nil, f.cookie); w.Code != 503 {
		t.Fatalf("offline remote=%d", w.Code)
	}
	if edge.tunnelCache["api"] != "" {
		t.Fatal("stale node cache was not invalidated")
	}
}

func TestWebInspectorDomainAppReplayPreservesIdentityGates(t *testing.T) {
	p, tunnel, pub := appProxyFixture(t)
	central := appSessionCookie(t, p, bryanEmail, "github", true, "")
	app := appSessionCookie(t, p, bryanEmail, "github", true, appHost)
	stream := tunnel.Stream.(*meteringFixtureStream)
	tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityHTTPOriginReplayV1: true}
	var forwarded []map[string]string
	stream.hook = func(msg *pb.TunnelMessage) error {
		if open := msg.GetConnectionOpen(); open != nil {
			forwarded = append(forwarded, open.HttpRequest.Headers)
		}
		if end := msg.GetConnectionHalfClose(); end != nil {
			webInspectorStreamReply(tunnel, end.ConnectionId, 200, "okay")
		}
		return nil
	}
	r := httptest.NewRequest("GET", "https://"+appHost+"/report", nil)
	r.AddCookie(app)
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("app ingress=%d %s", w.Code, w.Body)
	}
	event := tunnel.inspectionHistory().Snapshot()[0]
	if _, exists := event.Headers[identity.Header]; exists {
		t.Fatal("generated app assertion entered replay reconstruction")
	}
	if _, exists := event.Headers[identity.EmailHeader]; exists {
		t.Fatal("generated app identity entered replay reconstruction")
	}
	// The observer must not remove the freshly issued assertion from ingress.
	if len(forwarded) != 1 || forwarded[0][identity.Header] == "" {
		t.Fatal("inspection removed the app assertion")
	}
	source := httptest.NewRequest("GET", "https://tunn.test/account/inspect", nil)
	source.AddCookie(central)
	csrf, err := p.createCSRFToken(source, inspectorCSRFAction)
	if err != nil {
		t.Fatal(err)
	}
	binding := inspectorBinding(source)
	action, _, err := tunnel.inspectionHistory().Prepare(event.ID, binding, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"session": tunnel.inspectionHistory().Session(), "action": action, "confirmed": true}
	data, _ := json.Marshal(input)
	request := httptest.NewRequest("POST", fmt.Sprintf("https://tunn.test/api/inspector/%s/requests/%d/replay", tunnel.TunnelID, event.ID), strings.NewReader(string(data)))
	request.AddCookie(central)
	request.Header.Set("Origin", "https://tunn.test")
	request.Header.Set("X-Tunn-CSRF", csrf)
	request.Header.Set("Content-Type", "application/json")
	result := httptest.NewRecorder()
	p.createHandler().ServeHTTP(result, request)
	if result.Code != 200 || len(forwarded) != 2 {
		t.Fatalf("domain-app replay=%d %s", result.Code, result.Body)
	}
	assertion, err := jwt.Parse(forwarded[1][identity.Header], func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil || !assertion.Valid {
		t.Fatal("replay did not receive a signed app assertion")
	}
	claims := assertion.Claims.(jwt.MapClaims)
	if claims["sub"] != tunnel.AccountID {
		t.Fatal("replay identity was not the account owner")
	}
	if strings.Contains(forwarded[1]["Cookie"], central.Value) || strings.Contains(forwarded[1]["Cookie"], app.Value) {
		t.Fatal("platform session reached domain origin")
	}
}

func TestWebInspectorTruncatedReplayReturnsFailureEvent(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	f.tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityHTTPOriginReplayV1: true}
	truncate := false
	f.stream.hook = func(message *pb.TunnelMessage) error {
		if end := message.GetConnectionHalfClose(); end != nil {
			length := "4"
			if truncate {
				length = "5"
			}
			id := end.ConnectionId
			f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 202, Headers: map[string]string{"Content-Type": "text/plain", "Content-Length": length}}}}})
			f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte("four")}}})
			f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id}}})
		}
		return nil
	}
	event := f.seed(t)
	action := f.prepare(t, event)
	truncate = true
	result := f.call("POST", fmt.Sprintf("/api/inspector/api/requests/%d/replay", event.ID), f.replayInput(event, action), f.cookie, nil)
	if result.Code != 200 {
		t.Fatalf("replay failure was not reported=%d %s", result.Code, result.Body)
	}
	var out struct {
		Event inspection.Event `json:"event"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Event.ReplayOf != event.ID || out.Event.TerminalReason != "proxy_error" || out.Event.Reconstructable || out.Event.ResponseBytes != 4 {
		t.Fatalf("truncated replay result: %+v", out.Event)
	}
}

func webInspectorStreamReply(tunnel *TunnelConnection, id string, status int, body string) {
	tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: int32(status), Headers: map[string]string{"Content-Type": "application/json", "Content-Length": fmt.Sprint(len(body))}}}}})
	tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte(body)}}})
	tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id}}})
}
func TestWebInspectorOldPublisherHistoryWithoutReplay(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	event := f.seed(t)
	delete(f.tunnel.Capabilities, common.CapabilityHTTPOriginReplayV1)
	history := f.call("GET", "/api/inspector/api/requests", nil, f.cookie, nil)
	var out struct {
		Events    []inspection.Event `json:"events"`
		Supported bool               `json:"replay_supported"`
	}
	if err := json.Unmarshal(history.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if history.Code != 200 || len(out.Events) != 1 || out.Supported {
		t.Fatal("old publisher's read-only history unavailable")
	}
	prepared := f.call("POST", fmt.Sprintf("/api/inspector/api/requests/%d/prepare", event.ID), map[string]any{"session": f.tunnel.inspectionHistory().Session()}, f.cookie, nil)
	if prepared.Code != 409 || !strings.Contains(prepared.Body.String(), "Upgrade") || len(f.deliveries) != 1 {
		t.Fatal("unsafe replay allowed without publisher negotiation")
	}
}
