package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/store"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
)

type meteringFixtureStream struct {
	mockWebProxyStream
	hook func(*pb.TunnelMessage) error
}

func (s *meteringFixtureStream) Send(msg *pb.TunnelMessage) error {
	_ = s.mockWebProxyStream.Send(msg)
	if s.hook != nil {
		return s.hook(msg)
	}
	return nil
}

type meteringFixtureStorage struct{ mockStorage }

func (s *meteringFixtureStorage) GetEmailBucket(ctx context.Context, email string) ([]string, error) {
	return []string{email}, nil
}
func meteringRelay(t *testing.T, streaming bool, response string) (*ProxyServer, *TunnelConnection, *metering.Store, *meteringFixtureStream) {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ledger, err := metering.New(db)
	if err != nil {
		t.Fatal(err)
	}
	cfg := webproxyTestConfig()
	cfg.Domain = "tunn.test"
	stream := &meteringFixtureStream{}
	tunnel := &TunnelConnection{TunnelID: "api", CreatorEmail: "owner@example.com", AccountID: "owner-account", AllowedEmails: []string{"alice@example.com", "owner@example.com"}, Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse)}
	if streaming {
		tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true}
	}
	server := NewTunnelServer(cfg, nil, nil, nil)
	server.tunnels[tunnel.TunnelID] = tunnel
	p := &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: server, meter: ledger, storage: &meteringFixtureStorage{mockStorage: mockStorage{usage: make(map[string]int64)}}, quotaCache: NewQuotaCache(time.Minute), usageBuffer: NewUsageBuffer(), tunnelCache: make(map[string]string)}
	stream.hook = func(msg *pb.TunnelMessage) error {
		if req := msg.GetHttpRequest(); req != nil {
			tunnel.pendingMu.RLock()
			ch := tunnel.pendingRequests[req.ConnectionId]
			tunnel.pendingMu.RUnlock()
			ch <- &pb.HttpResponse{ConnectionId: req.ConnectionId, StatusCode: 200, Headers: map[string]string{"Content-Type": "text/plain", "Tunn-Request-ID": "spoofed"}, Body: []byte(response)}
		}
		if end := msg.GetConnectionHalfClose(); end != nil {
			id := end.ConnectionId
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/plain", "Tunn-Request-ID": "spoofed"}}}}})
			midpoint := len(response) / 2
			for _, chunk := range []string{response[:midpoint], response[midpoint:]} {
				if chunk != "" {
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte(chunk)}}})
				}
			}
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id}}})
		}
		return nil
	}
	return p, tunnel, ledger, stream
}
func relayGrant(t *testing.T, ledger *metering.Store, requests, bytes int64) (*meterpb.Grant, string) {
	t.Helper()
	token := "tunn_gr_" + fmt.Sprintf("fixture-%d-%d", requests, bytes)
	digest := sha256.Sum256([]byte(token))
	g, err := ledger.CreateGrant(context.Background(), &meterpb.Grant{Owner: "owner@example.com", Endpoint: "api", TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), MonthlyRequests: requests, MonthlyBytes: bytes})
	if err != nil {
		t.Fatal(err)
	}
	return g, token
}
func relayRequest(token, body string) *http.Request {
	r := httptest.NewRequest("POST", "https://api.tunn.test/secret-path?api_key=not-for-audit", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Tunn-Authorization", "Bearer "+token)
	}
	return r
}
func relayExport(t *testing.T, ledger metering.Backend) *meterpb.ExportResponse {
	t.Helper()
	out, err := ledger.Export(context.Background(), &meterpb.ExportRequest{Owner: "owner@example.com", Endpoint: "api", Month: time.Now().UTC().Format("2006-01")})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func relayJWT(t *testing.T, p *ProxyServer, email string) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"email": email, "exp": time.Now().Add(time.Hour).Unix()}).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMeteringBufferedAndStreamingAccuracy(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			p, _, ledger, stream := meteringRelay(t, streaming, "response-data")
			g, token := relayGrant(t, ledger, 1, 1000000)
			body := strings.Repeat("body", 20000)
			r := relayRequest(token, body)
			r.Header.Set("Authorization", "Bearer upstream-secret")
			r.Header.Set("Cookie", "tunn_auth=platform-secret; app_cookie=keep")
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, r)
			if rec.Code != 200 || rec.Body.String() != "response-data" {
				t.Fatalf("response=%d %s", rec.Code, rec.Body.String())
			}
			out := relayExport(t, ledger)
			if len(out.Events) != 1 || len(out.Usage) != 1 {
				t.Fatal(out)
			}
			u, e := out.Usage[0], out.Events[0]
			if u.Caller != "grant:"+g.Id || u.AdmittedRequests != 1 || u.Requests != 1 || u.RequestBytes != int64(len(body)) || u.ResponseBytes != 13 || !e.Finished || !e.Forwarded || e.Status != 200 {
				t.Fatalf("usage=%v event=%v", u, e)
			}
			if rec.Header().Get("Tunn-Request-ID") != e.RequestId || rec.Header().Get("Tunn-Requests-Remaining") != "0" {
				t.Fatal(rec.Header())
			}
			if account := p.storage.(*meteringFixtureStorage).usage["owner-account"]; account != u.RequestBytes+u.ResponseBytes {
				t.Fatalf("account counted %d", account)
			}
			stream.mu.Lock()
			messages := append([]*pb.TunnelMessage(nil), stream.sentMsgs...)
			stream.mu.Unlock()
			for _, msg := range messages {
				var headers map[string]string
				if req := msg.GetHttpRequest(); req != nil {
					headers = req.Headers
				}
				if open := msg.GetConnectionOpen(); open != nil {
					headers = open.HttpRequest.Headers
				}
				if headers != nil {
					if headers["Tunn-Authorization"] != "" || headers["Authorization"] != "Bearer upstream-secret" || headers["Cookie"] != "app_cookie=keep" {
						t.Fatal(headers)
					}
				}
			}
			data, _ := json.Marshal(out)
			if bytes.Contains(data, []byte("secret")) || bytes.Contains(data, []byte(token)) {
				t.Fatalf("audit contains payload/credential: %s", data)
			}
			rec = httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, relayRequest(token, ""))
			if rec.Code != 429 || rec.Header().Get("Tunn-Limit-Reason") != "request_budget" || rec.Header().Get("Retry-After") == "" {
				t.Fatalf("boundary=%d %v", rec.Code, rec.Header())
			}
			out = relayExport(t, ledger)
			if out.Usage[0].Requests != 2 || out.Usage[0].AdmittedRequests != 1 || out.Usage[0].ResponseBytes != 13 {
				t.Fatal(out)
			}
		})
	}
}
func TestMeteringBudgetKnownInputAndBufferedResponse(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			p, _, ledger, stream := meteringRelay(t, streaming, "response")
			_, token := relayGrant(t, ledger, 0, 7)
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, relayRequest(token, "12345678"))
			if rec.Code != 429 {
				t.Fatalf("oversized input=%d", rec.Code)
			}
			stream.mu.Lock()
			sent := len(stream.sentMsgs)
			stream.mu.Unlock()
			if sent != 0 {
				t.Fatal("oversized known body reached publisher")
			}
			out := relayExport(t, ledger)
			if out.Usage[0].AdmittedRequests != 0 || out.Usage[0].RequestBytes != 0 || out.Usage[0].ResponseBytes != 0 {
				t.Fatal(out)
			}
			rec = httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, relayRequest(token, "123"))
			if streaming {
				if rec.Code != 200 || rec.Body.String() != "resp" || rec.Result().Trailer.Get("Tunn-Limit-Reason") != "byte_budget" {
					t.Fatalf("stream boundary=%d %q %v", rec.Code, rec.Body.String(), rec.Result().Trailer)
				}
			} else {
				if rec.Code != 429 || rec.Header().Get("Tunn-Limit-Reason") != "byte_budget" {
					t.Fatalf("buffered boundary=%d %v", rec.Code, rec.Header())
				}
			}
			out = relayExport(t, ledger)
			wantResponse := int64(0)
			if streaming {
				wantResponse = 4
			}
			if out.Usage[0].RequestBytes != 3 || out.Usage[0].ResponseBytes != wantResponse || out.Events[1].Reason != "byte_budget" {
				t.Fatal(out)
			}
		})
	}
}
func TestMeteringUnknownInputCannotOverspend(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			p, _, ledger, stream := meteringRelay(t, streaming, "")
			_, token := relayGrant(t, ledger, 0, 3)
			r := relayRequest(token, "123456")
			r.ContentLength = -1
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, r)
			if rec.Code != 429 || rec.Header().Get("Tunn-Limit-Reason") != "byte_budget" {
				t.Fatalf("response=%d %v", rec.Code, rec.Header())
			}
			out := relayExport(t, ledger)
			if out.Usage[0].RequestBytes != 3 || out.Usage[0].ResponseBytes != 0 {
				t.Fatal(out)
			}
			stream.mu.Lock()
			defer stream.mu.Unlock()
			for _, msg := range stream.sentMsgs {
				if req := msg.GetHttpRequest(); req != nil {
					t.Fatal("incomplete buffered request forwarded")
				}
				if data := msg.GetConnectionData(); data != nil && len(data.Data) > 3 {
					t.Fatal("over-budget streamed input forwarded")
				}
			}
		})
	}
}

type meteringShortWriter struct {
	header  http.Header
	status  int
	written int
}

func (w *meteringShortWriter) Header() http.Header    { return w.header }
func (w *meteringShortWriter) WriteHeader(status int) { w.status = status }
func (w *meteringShortWriter) Write(body []byte) (int, error) {
	n := min(2, len(body))
	w.written += n
	return n, io.ErrClosedPipe
}
func TestMeteringDisconnectSettlesPartialWrites(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			p, _, ledger, _ := meteringRelay(t, streaming, "response")
			_, token := relayGrant(t, ledger, 0, 100)
			w := &meteringShortWriter{header: make(http.Header)}
			p.createHandler().ServeHTTP(w, relayRequest(token, "123"))
			out := relayExport(t, ledger)
			if w.status != 200 || w.written != 2 || out.Usage[0].RequestBytes != 3 || out.Usage[0].ResponseBytes != 2 || out.Events[0].Status != 200 || out.Events[0].Reason != "proxy_failure" {
				t.Fatalf("writer=%+v export=%v", w, out)
			}
			if account := p.storage.(*meteringFixtureStorage).usage["owner-account"]; account != 5 {
				t.Fatal(account)
			}
		})
	}
}
func TestMeteringCancellationAndPreheaderFailure(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			p, _, ledger, stream := meteringRelay(t, streaming, "")
			_, token := relayGrant(t, ledger, 0, 100)
			stream.hook = func(msg *pb.TunnelMessage) error { return io.ErrClosedPipe }
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, relayRequest(token, "123"))
			out := relayExport(t, ledger)
			if rec.Code != 502 || len(out.Events) != 1 || out.Events[0].Reason != "proxy_failure" || !out.Events[0].Finished {
				t.Fatalf("response=%d export=%v", rec.Code, out)
			}
			if !streaming && out.Usage[0].RequestBytes != 3 {
				t.Fatal(out)
			}
		})
	}
	p, _, ledger, stream := meteringRelay(t, false, "")
	_, token := relayGrant(t, ledger, 0, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := relayRequest(token, "123").WithContext(ctx)
	stream.hook = func(*pb.TunnelMessage) error { cancel(); return nil }
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, r)
	out := relayExport(t, ledger)
	if len(out.Events) != 1 || out.Events[0].Reason != "caller_disconnected" || out.Usage[0].RequestBytes != 3 {
		t.Fatal(out)
	}
}
func TestMeteringRejectionsAndPublicGrantCannotFallback(t *testing.T) {
	p, tunnel, ledger, stream := meteringRelay(t, false, "ok")
	r := relayRequest(relayJWT(t, p, "stranger@example.com"), "")
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, r)
	if rec.Code != 403 {
		t.Fatal(rec.Code)
	}
	rec = httptest.NewRecorder()
	r = relayRequest("not-a-token", "")
	p.createHandler().ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatal(rec.Code)
	}
	out := relayExport(t, ledger)
	if len(out.Events) != 2 || out.Events[0].Caller != "email:stranger@example.com" || out.Events[0].Reason != "allowlist_denied" || out.Events[1].Reason != "authentication_required" {
		t.Fatal(out)
	}
	g, token := relayGrant(t, ledger, 0, 100)
	if _, err := ledger.RevokeGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	tunnel.AllowedEmails = nil
	r = relayRequest(token, "")
	r.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, p, tunnel.CreatorEmail)})
	rec = httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, r)
	if rec.Code != 403 || rec.Header().Get("Tunn-Limit-Reason") != "grant_revoked" {
		t.Fatalf("public fallback=%d %v", rec.Code, rec.Header())
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if len(stream.sentMsgs) != 0 {
		t.Fatal("rejected traffic reached publisher")
	}
}
func TestMeteringCallerIdentityEmailTokenAnonymous(t *testing.T) {
	p, tunnel, ledger, _ := meteringRelay(t, false, "ok")
	tunnel.AllowedEmails = nil
	token := "tunn_ep_existing-endpoint-token"
	digest := sha256.Sum256([]byte(token))
	tunnel.AccessTokenSHA256 = digest[:]
	for _, credential := range []string{relayJWT(t, p, "alice@example.com"), token, ""} {
		rec := httptest.NewRecorder()
		p.createHandler().ServeHTTP(rec, relayRequest(credential, ""))
		if rec.Code != 200 {
			t.Fatal(rec.Code)
		}
	}
	out := relayExport(t, ledger)
	got := map[string]bool{}
	for _, u := range out.Usage {
		got[u.Caller] = true
	}
	if len(got) != 3 || !got["anonymous"] || !got["email:alice@example.com"] || !got[metering.TokenID(digest[:])] {
		t.Fatal(got)
	}
}
func TestMeteringOwnerAPI(t *testing.T) {
	p, _, ledger, _ := meteringRelay(t, false, "ok")
	ownerJWT := relayJWT(t, p, "owner@example.com")
	digest := sha256.Sum256([]byte("tunn_gr_owner-api-fixture"))
	g := &meterpb.Grant{Consumer: "agent@example.com", TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), MonthlyRequests: 2, MonthlyBytes: 100}
	data, _ := json.Marshal(g)
	call := func(method, path, token string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://tunn.test"+path, bytes.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		p.createHandler().ServeHTTP(rec, r)
		return rec
	}
	path := "/api/endpoints/api/grants"
	if rec := call("POST", path, relayJWT(t, p, "stranger@example.com"), data); rec.Code != 403 {
		t.Fatal(rec.Code)
	}
	if rec := call("POST", path, "", data); rec.Code != 401 {
		t.Fatal(rec.Code)
	}
	if rec := call("POST", path, ownerJWT, append(append([]byte(nil), data...), []byte(" {}")...)); rec.Code != 400 {
		t.Fatal(rec.Code)
	}
	rec := call("POST", path, ownerJWT, data)
	if rec.Code != 201 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create=%d %s", rec.Code, rec.Body.String())
	}
	created := new(meterpb.Grant)
	if err := json.Unmarshal(rec.Body.Bytes(), created); err != nil {
		t.Fatal(err)
	}
	if created.Id == "" || len(created.TokenSha256) > 0 {
		t.Fatal(created)
	}
	if rec := call("DELETE", path+"/"+created.Id, relayJWT(t, p, "stranger@example.com"), nil); rec.Code != 404 {
		t.Fatal(rec.Code)
	}
	if rec := call("DELETE", path+"/"+created.Id, ownerJWT, nil); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	for _, path := range []string{"/api/grants", "/api/endpoints/api/grants"} {
		rec := call("GET", path, ownerJWT, nil)
		var listed meterpb.ListGrantsResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &listed) != nil || len(listed.Grants) != 1 || !listed.Grants[0].Revoked || len(listed.Grants[0].TokenSha256) != 0 {
			t.Fatalf("list=%d %s", rec.Code, rec.Body.String())
		}
		if rec := call("GET", path, relayJWT(t, p, "stranger@example.com"), nil); rec.Code != 200 || strings.Contains(rec.Body.String(), created.Id) {
			t.Fatalf("owner isolation=%d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := call("GET", "/api/endpoints/api/usage?month=invalid", ownerJWT, nil); rec.Code != 400 {
		t.Fatal(rec.Code)
	}
	if rec := call("GET", "/api/endpoints/api/usage", ownerJWT, nil); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	for _, path := range []string{"/api/usage?since=bad", "/api/usage?since=0s", "/api/usage?since=1h&month=2026-10", "/api/usage?tunnel=../api"} {
		if rec := call("GET", path, ownerJWT, nil); rec.Code != 400 && rec.Code != 404 {
			t.Fatalf("accepted %s: %d", path, rec.Code)
		}
	}
	p.createHandler().ServeHTTP(httptest.NewRecorder(), relayRequest(relayJWT(t, p, "alice@example.com"), "abc"))
	for _, path := range []string{"/api/usage", "/api/usage?tunnel=api&since=1h", "/api/endpoints/api/usage?since=1h"} {
		rec := call("GET", path, ownerJWT, nil)
		var usage meterpb.ExportResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &usage) != nil || usage.OwnerUsage == nil || usage.OwnerUsage.TotalBytes != 5 || usage.OwnerUsage.Requests != 1 {
			t.Fatalf("usage %s=%d %s", path, rec.Code, rec.Body.String())
		}
		if rec := call("GET", path, "", nil); rec.Code != 401 {
			t.Fatalf("unauthenticated usage=%d", rec.Code)
		}
	}
	resolved, err := ledger.Resolve(context.Background(), &meterpb.ResolveRequest{Owner: created.Owner, Endpoint: created.Endpoint, TokenSha256: digest[:]})
	if err != nil || !resolved.Revoked {
		t.Fatalf("grant=%v %v", resolved, err)
	}
}

func TestMeteringOwnerCapsEnforceOnBothHTTPPaths(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprintf("streaming=%v", streaming), func(t *testing.T) {
			p, _, _, stream := meteringRelay(t, streaming, "response")
			// Apply a shared cap to this fixture's ingress ledger.
			local := p.storage.(*meteringFixtureStorage)
			db, err := store.InitForTest()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			ledger, err := metering.New(db, metering.WithOwnerBudgets(1, 12))
			if err != nil {
				t.Fatal(err)
			}
			p.meter = ledger
			jwt := relayJWT(t, p, "alice@example.com")
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, relayRequest(jwt, "data"))
			if rec.Code != 200 || rec.Body.String() != "response" || rec.Header().Get("Tunn-Requests-Remaining") != "0" {
				t.Fatalf("admitted=%d %s %v", rec.Code, rec.Body.String(), rec.Header())
			}
			messageCount := func() int {
				stream.mu.Lock()
				defer stream.mu.Unlock()
				return len(stream.sentMsgs)
			}
			before := messageCount()
			rec = httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, relayRequest(jwt, "data"))
			if rec.Code != 429 || rec.Header().Get("Tunn-Limit-Reason") != "owner_request_budget" || messageCount() != before || local.usage["owner-account"] != 12 {
				t.Fatalf("denied=%d %v account=%d", rec.Code, rec.Header(), local.usage["owner-account"])
			}
		})
	}
}

func TestMeteringKnownResponseReportsTighterOwnerBudget(t *testing.T) {
	p, tunnel, _, _ := meteringRelay(t, false, "")
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ledger, err := metering.New(db, metering.WithOwnerBudgets(0, 5))
	if err != nil {
		t.Fatal(err)
	}
	p.meter = ledger
	g, token := relayGrant(t, ledger, 10, 100)
	session := newIngressMeter(p, tunnel)
	session.event.Caller, session.event.GrantId = "grant:"+g.Id, g.Id
	rec := httptest.NewRecorder()
	if !session.admit(context.Background(), rec, relayRequest(token, "a")) {
		t.Fatal(rec.Body.String())
	}
	if _, err := session.charge(context.Background(), true, 1); err != nil {
		t.Fatal(err)
	}
	var limit *ingressLimitError
	if err := session.checkResponse(context.Background(), 5); !errors.As(err, &limit) || limit.decision.Reason != "owner_byte_budget" || limit.decision.Status != 429 || limit.decision.BytesRemaining != 4 {
		t.Fatalf("response preflight=%v", err)
	}
	if out := relayExport(t, ledger); out.OwnerUsage.RequestBytes != 1 || out.OwnerUsage.ResponseBytes != 0 {
		t.Fatalf("response preflight reserved rejected bytes: %v", out)
	}
}
func TestMeteringAuthorityFailureClosesIngress(t *testing.T) {
	p, _, _, stream := meteringRelay(t, false, "ok")
	p.meter = &metering.Remote{Connection: func() *grpc.ClientConn { return nil }}
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, relayRequest(relayJWT(t, p, "alice@example.com"), ""))
	if rec.Code != 503 {
		t.Fatal(rec.Code)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if len(stream.sentMsgs) != 0 {
		t.Fatal("ledger outage forwarded traffic")
	}
}

func TestMeteringHeadMetadataDoesNotConsumeByteBudget(t *testing.T) {
	p, tunnel, ledger, stream := meteringRelay(t, true, "")
	_, token := relayGrant(t, ledger, 0, 3)
	stream.hook = func(msg *pb.TunnelMessage) error {
		if end := msg.GetConnectionHalfClose(); end != nil {
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: end.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 200, Headers: map[string]string{"content-length": "1000000"}}}}})
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: end.ConnectionId}}})
		}
		return nil
	}
	r := relayRequest(token, "")
	r.Method = http.MethodHead
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, r)
	if rec.Code != 200 || rec.Header().Get("Content-Length") != "1000000" || rec.Body.Len() != 0 {
		t.Fatalf("HEAD=%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	out := relayExport(t, ledger)
	if out.Usage[0].RequestBytes != 0 || out.Usage[0].ResponseBytes != 0 {
		t.Fatal(out)
	}
}
func TestMeteringAccountQuotaUsesAccountID(t *testing.T) {
	p, _, ledger, stream := meteringRelay(t, false, "ok")
	p.storage.(*meteringFixtureStorage).usage["owner-account"] = FreeQuotaBytes
	_, token := relayGrant(t, ledger, 100, 100)
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, relayRequest(token, "123"))
	if rec.Code != 429 {
		t.Fatalf("account quota bypassed: %d", rec.Code)
	}
	out := relayExport(t, ledger)
	if len(out.Events) != 1 || out.Events[0].Reason != "account_quota" || out.Usage[0].AdmittedRequests != 0 || out.Usage[0].RequestBytes != 0 {
		t.Fatal(out)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if len(stream.sentMsgs) != 0 {
		t.Fatal("over-quota account reached publisher")
	}
}

func TestMeteringSelfHostPreservesApplicationJWTWithoutPlatformKey(t *testing.T) {
	p, tunnel, ledger, stream := meteringRelay(t, false, "ok")
	appJWT := relayJWT(t, p, "application@example.com")
	p.config.Environment = config.EnvProd
	p.config.JWTSecret = ""
	tunnel.AllowedEmails = nil
	r := relayRequest("", "")
	r.Header.Set("Authorization", "Bearer "+appJWT)
	r.AddCookie(&http.Cookie{Name: authCookieName, Value: appJWT})
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("self-hosted application JWT broke public ingress: %d", rec.Code)
	}
	out := relayExport(t, ledger)
	if out.Usage[0].Caller != "anonymous" {
		t.Fatal(out)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for _, msg := range stream.sentMsgs {
		if req := msg.GetHttpRequest(); req != nil {
			if req.Headers["Authorization"] != "Bearer "+appJWT || req.Headers["Cookie"] != "" {
				t.Fatal("application JWT or platform cookie forwarding changed")
			}
		}
	}
}
