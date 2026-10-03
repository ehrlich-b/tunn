package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type ingressTestStream struct {
	mockWebProxyStream
	tunnel            *TunnelConnection
	openID            string
	response          []byte
	failBeforeHeaders bool
	failAfterBody     bool
}

func (s *ingressTestStream) Send(msg *pb.TunnelMessage) error {
	if req := msg.GetHttpRequest(); req != nil {
		s.tunnel.pendingMu.RLock()
		ch := s.tunnel.pendingRequests[req.ConnectionId]
		s.tunnel.pendingMu.RUnlock()
		ch <- &pb.HttpResponse{ConnectionId: req.ConnectionId, StatusCode: 200, Body: s.response}
	}
	if open := msg.GetConnectionOpen(); open != nil {
		s.openID = open.ConnectionId
	}
	if msg.GetConnectionHalfClose() != nil {
		if s.failBeforeHeaders {
			s.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{ConnectionClose: &pb.ConnectionClose{ConnectionId: s.openID, ErrorMessage: "synthetic failure"}}})
			return nil
		}
		s.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: s.openID, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 200}}}})
		s.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: s.openID, Data: s.response}}})
		if s.failAfterBody {
			s.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{ConnectionClose: &pb.ConnectionClose{ConnectionId: s.openID, ErrorMessage: "synthetic disconnect"}}})
		} else {
			s.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: s.openID}}})
		}
	}
	return nil
}

func newIngressProxy(t testing.TB, streaming bool) (*ProxyServer, *storage.LocalStorage, *TunnelConnection, *ingressTestStream) {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	local := storage.NewLocalStorage(db)
	owner, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	cfg := webproxyTestConfig()
	stream := &ingressTestStream{response: []byte("response")}
	digest := sha256.Sum256([]byte("synthetic-endpoint-token"))
	tunnel := &TunnelConnection{TunnelID: "tools", AccountID: owner.ID, CreatorEmail: owner.PrimaryEmail, AllowedEmails: []string{"alice@example.test"}, Plan: "free", Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse), AccessTokenSHA256: digest[:]}
	if streaming {
		tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true}
	}
	stream.tunnel = tunnel
	ts := NewTunnelServer(cfg, nil, nil, local)
	ts.tunnels[tunnel.TunnelID] = tunnel
	p := &ProxyServer{Domain: cfg.Domain, config: cfg, storage: local, tunnelServer: ts, usageBuffer: NewUsageBuffer(), quotaCache: NewQuotaCache(time.Second), tunnelCache: make(map[string]string)}
	return p, local, tunnel, stream
}
func ingressJWT(t *testing.T, p *ProxyServer, email string) string {
	t.Helper()
	w := httptest.NewRecorder()
	if err := p.setAuthCookie(w, email); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies()[0].Value
}
func exportIngress(t *testing.T, local storage.IngressStorage, id string, counters bool) *store.IngressExport {
	t.Helper()
	out, err := local.ExportIngress(context.Background(), store.IngressQuery{AccountID: id, Month: time.Now().UTC().Format("2006-01"), Limit: 500, Counters: counters})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIngressAttributionAndDecisions(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, kind := range []string{"bearer", "cookie", "capability", "anonymous", "denied", "invalid", "redirect", "quota"} {
			t.Run(kind+map[bool]string{false: "/buffered", true: "/streaming"}[streaming], func(t *testing.T) {
				p, local, tunnel, _ := newIngressProxy(t, streaming)
				req := httptest.NewRequest(http.MethodPost, "https://tools.tunn.to/mcp?secret=never-store", strings.NewReader("request"))
				req.Header.Set("X-Tunn-Caller", "owner@example.test")
				req.Header.Set("X-Tunn-Request-ID", "forged")
				expectedCaller, method, reason, outcome, statusCode := "email:alice@example.test", "bearer", "allow_list", "completed", 200
				switch kind {
				case "bearer":
					req.Header.Set("Tunn-Authorization", "Bearer "+ingressJWT(t, p, "Alice@Example.Test"))
				case "cookie":
					method = "cookie"
					req.AddCookie(&http.Cookie{Name: authCookieName, Value: ingressJWT(t, p, "alice@example.test")})
					req.Header.Set("Tunn-Authorization", "Bearer must-not-leak")
				case "capability":
					expectedCaller = "endpoint-token"
					method = "endpoint_token"
					reason = "endpoint_token"
					req.Header.Set("Tunn-Authorization", "Bearer synthetic-endpoint-token")
				case "anonymous":
					tunnel.AllowedEmails = nil
					expectedCaller = "anonymous"
					method = "none"
					reason = "open"
					req.Header.Set("Authorization", "Bearer upstream-only")
				case "denied":
					expectedCaller = "email:bob@example.test"
					reason = "access_denied"
					outcome = "denied"
					statusCode = 403
					req.Header.Set("Tunn-Authorization", "Bearer "+ingressJWT(t, p, "bob@example.test"))
				case "invalid":
					expectedCaller = "anonymous"
					method = "none"
					reason = "authentication_required"
					outcome = "denied"
					statusCode = 401
					req.Header.Set("Tunn-Authorization", "Bearer invalid-credential")
				case "redirect":
					expectedCaller = "anonymous"
					method = "none"
					reason = "authentication_required"
					outcome = "denied"
					statusCode = 302
					req.URL.Path = "/ordinary"
				case "quota":
					reason = "owner_quota_exceeded"
					outcome = "denied"
					statusCode = 429
					req.Header.Set("Tunn-Authorization", "Bearer "+ingressJWT(t, p, "alice@example.test"))
					if err := local.RecordUsage(context.Background(), tunnel.AccountID, FreeQuotaBytes); err != nil {
						t.Fatal(err)
					}
				}
				w := httptest.NewRecorder()
				p.handleWebProxy(w, req)
				if w.Code != statusCode {
					t.Fatalf("status=%d body=%s", w.Code, w.Body)
				}
				out := exportIngress(t, local, tunnel.AccountID, false)
				if len(out.Events) != 1 {
					t.Fatalf("events=%+v", out)
				}
				e := out.Events[0]
				if e.CallerID != expectedCaller || e.AuthMethod != method || e.Reason != reason || e.Outcome != outcome || e.Status != statusCode || e.RequestID == "forged" {
					t.Fatalf("event=%+v", e)
				}
				wantBytes := int64(15)
				if outcome == "denied" {
					wantBytes = 0
				}
				if e.RequestBytes+e.ResponseBytes != wantBytes || e.Forwarded != (outcome == "completed") {
					t.Fatalf("units=%+v", e)
				}
				usage, err := local.GetMonthlyUsage(context.Background(), tunnel.AccountID)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "quota" {
					wantBytes = FreeQuotaBytes
				}
				if usage != wantBytes {
					t.Fatalf("owner quota usage=%d want %d", usage, wantBytes)
				}
				raw, _ := json.Marshal(out)
				for _, secret := range []string{"never-store", "request\"", "response\"", "invalid-credential", "synthetic-endpoint-token", "forged"} {
					if bytes.Contains(raw, []byte(secret)) {
						t.Fatalf("sensitive data in export: %s", raw)
					}
				}
			})
		}
	}
}

type ingressPartialWriter struct{ *httptest.ResponseRecorder }

func (w ingressPartialWriter) Write(b []byte) (int, error) {
	_, _ = w.ResponseRecorder.Write(b[:2])
	return 2, io.ErrClosedPipe
}
func TestIngressPartialFailures(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, kind := range []string{"partial_write", "before_headers", "after_body", "canceled"} {
			if !streaming && (kind == "before_headers" || kind == "after_body") {
				continue
			}
			t.Run(kind+map[bool]string{false: "/buffered", true: "/streaming"}[streaming], func(t *testing.T) {
				p, local, tunnel, stream := newIngressProxy(t, streaming)
				req := httptest.NewRequest(http.MethodPost, "https://tools.tunn.to/mcp", strings.NewReader("request"))
				req.Header.Set("Tunn-Authorization", "Bearer synthetic-endpoint-token")
				w := httptest.NewRecorder()
				var writer http.ResponseWriter = w
				wantResponse := int64(8)
				wantStatus := 200
				wantOutcome := "proxy_error"
				switch kind {
				case "partial_write":
					writer = ingressPartialWriter{w}
					wantResponse = 2
				case "before_headers":
					stream.failBeforeHeaders = true
					wantResponse = 0
					wantStatus = 502
				case "after_body":
					stream.failAfterBody = true
				case "canceled":
					// A canceled legacy request with no response must finish immediately.
					ctx, cancel := context.WithCancel(req.Context())
					cancel()
					req = req.WithContext(ctx)
					wantOutcome = "canceled"
					wantResponse = 0
					wantStatus = 502
					tunnel.Stream = &mockWebProxyStream{}
				}
				p.handleWebProxy(writer, req)
				e := exportIngress(t, local, tunnel.AccountID, false).Events[0]
				if e.Status != wantStatus || e.Outcome != wantOutcome || e.ResponseBytes != wantResponse {
					t.Fatalf("event=%+v", e)
				}
				usage, err := local.GetMonthlyUsage(context.Background(), tunnel.AccountID)
				if err != nil {
					t.Fatal(err)
				}
				if usage != e.RequestBytes+e.ResponseBytes {
					t.Fatalf("quota=%d event=%+v", usage, e)
				}
			})
		}
	}
}

func TestIngressOwnerExportAuthorizationAndRouting(t *testing.T) {
	p, local, tunnel, _ := newIngressProxy(t, false)
	ownerToken := ingressJWT(t, p, tunnel.CreatorEmail)
	for _, email := range []string{"owner@example.test", "other@example.test"} {
		if _, err := local.FindOrCreateByEmails(context.Background(), []string{email}, "github"); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "https://tools.tunn.to/mcp", nil)
	req.Header.Set("Tunn-Authorization", "Bearer synthetic-endpoint-token")
	p.handleWebProxy(httptest.NewRecorder(), req)
	for _, tc := range []struct {
		token  string
		query  string
		want   int
		events int
	}{
		{ownerToken, "?account_id=forged", 200, 1}, {ingressJWT(t, p, "other@example.test"), "?endpoint=tools", 200, 0},
		{"synthetic-endpoint-token", "", 401, 0}, {"", "", 401, 0}, {ownerToken, "?limit=501", 400, 0}, {ownerToken, "?after=-1", 400, 0}, {ownerToken, "?month=2026-13", 400, 0},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://tunn.to/api/usage"+tc.query, nil)
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != tc.want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("export=%d %s", w.Code, w.Body)
		}
		if w.Code == 200 {
			var out store.IngressExport
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if len(out.Events) != tc.events || out.Billable {
				t.Fatalf("export=%+v", out)
			}
		}
	}
	// The same path on an endpoint is still an application request.
	r := httptest.NewRequest(http.MethodPost, "https://tools.tunn.to/api/usage", strings.NewReader("app"))
	r.Header.Set("Authorization", "Bearer synthetic-endpoint-token")
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "response" {
		t.Fatalf("app route=%d %s", w.Code, w.Body)
	}
}

type ambiguousIngressStorage struct {
	*storage.LocalStorage
	fail bool
}

func (s *ambiguousIngressStorage) RecordIngress(ctx context.Context, e store.IngressEvent) error {
	if err := s.LocalStorage.RecordIngress(ctx, e); err != nil {
		return err
	}
	if s.fail {
		return errors.New("synthetic lost acknowledgement")
	}
	return nil
}
func TestIngressRetryAfterAmbiguousCommit(t *testing.T) {
	p, local, tunnel, _ := newIngressProxy(t, false)
	unreliable := &ambiguousIngressStorage{LocalStorage: local, fail: true}
	p.storage = unreliable
	req := httptest.NewRequest(http.MethodGet, "https://tools.tunn.to/mcp", nil)
	req.Header.Set("Authorization", "Bearer synthetic-endpoint-token")
	p.handleWebProxy(httptest.NewRecorder(), req)
	if len(p.pendingIngress) != 1 {
		t.Fatalf("pending=%d", len(p.pendingIngress))
	}
	unreliable.fail = false
	p.flushIngress(context.Background())
	out := exportIngress(t, local, tunnel.AccountID, true)
	if len(p.pendingIngress) != 0 || len(out.Counters) != 1 || out.Counters[0].Requests != 1 {
		t.Fatalf("retry double counted: %+v", out)
	}
	usage, err := local.GetMonthlyUsage(context.Background(), tunnel.AccountID)
	if err != nil || usage != 8 {
		t.Fatalf("ambiguous retry charged quota twice: %d %v", usage, err)
	}
}

func ingressProxyStorage(t *testing.T, local *storage.LocalStorage) *storage.ProxyStorage {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor("synthetic-node-secret")))
	internalv1.RegisterLoginNodeDBServer(server, NewLoginNodeDBServer(local))
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///synthetic-login", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(metadata.AppendToOutgoingContext(ctx, "x-node-secret", "synthetic-node-secret"), method, req, reply, cc, opts...)
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	proxy := storage.NewProxyStorage()
	proxy.SetConnection(conn)
	return proxy
}
func TestIngressInternalRPC(t *testing.T) {
	_, local, tunnel, _ := newIngressProxy(t, false)
	remote := ingressProxyStorage(t, local)
	e := store.IngressEvent{RequestID: "rpc-id", AccountID: tunnel.AccountID, EndpointID: "tools", CallerID: "anonymous", AuthMethod: "none", Reason: "authentication_required", Outcome: "denied", Status: 401, StartedAt: time.Now().UTC()}
	for i := 0; i < 2; i++ {
		if err := remote.RecordIngress(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	out := exportIngress(t, remote, tunnel.AccountID, true)
	if len(out.Counters) != 1 || out.Counters[0].Requests != 1 || out.Counters[0].Denied != 1 {
		t.Fatalf("RPC counters=%+v", out)
	}
	e.RequestBytes = -1
	if err := remote.RecordIngress(context.Background(), e); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid metadata=%v", err)
	}
}

type earlyIngressStream struct {
	mockWebProxyStream
	tunnel *TunnelConnection
}

func (s *earlyIngressStream) Send(msg *pb.TunnelMessage) error {
	if open := msg.GetConnectionOpen(); open != nil {
		s.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 401}}}})
		s.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte("early")}}})
		s.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId}}})
	}
	return nil
}
func TestIngressEarlyResponseStopsUpload(t *testing.T) {
	p, local, tunnel, _ := newIngressProxy(t, true)
	tunnel.Stream = &earlyIngressStream{tunnel: tunnel}
	reader, writer := io.Pipe()
	defer writer.Close()
	req := httptest.NewRequest(http.MethodPost, "https://tools.tunn.to/mcp", reader)
	req.Header.Set("Authorization", "Bearer synthetic-endpoint-token")
	done := make(chan struct{})
	go func() { p.handleWebProxy(httptest.NewRecorder(), req); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("early response left upload blocked")
	}
	e := exportIngress(t, local, tunnel.AccountID, false).Events[0]
	if e.Status != 401 || e.Outcome != "completed" || e.RequestBytes != 0 || e.ResponseBytes != 5 {
		t.Fatalf("early response=%+v", e)
	}
}

// Compare the accounting cost in a synthetic buffered HTTP fixture. This excludes
// network latency and represents an in-memory SQLite path, not a service SLO.
type quotaOnlyStorage struct{ storage.Storage }

func BenchmarkIngressHTTP(b *testing.B) {
	for _, ledger := range []bool{false, true} {
		b.Run(map[bool]string{false: "quota_only", true: "with_ledger"}[ledger], func(b *testing.B) {
			p, local, tunnel, _ := newIngressProxy(b, false)
			if !ledger {
				p.storage = quotaOnlyStorage{local}
			}
			tunnel.AllowedEmails = nil
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req := httptest.NewRequest(http.MethodPost, "https://tools.tunn.to/api", strings.NewReader("request"))
				p.handleWebProxy(httptest.NewRecorder(), req)
			}
		})
	}
}

func TestIngressInternalMethodsRequireNodeSecret(t *testing.T) {
	for _, method := range []string{"/internal.LoginNodeDB/RecordIngress", "/internal.LoginNodeDB/ExportIngress"} {
		invoked := false
		_, err := nodeSecretInterceptor("synthetic-secret")(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, any) (any, error) { invoked = true; return nil, nil })
		if invoked || status.Code(err) != codes.Unauthenticated {
			t.Fatalf("unauthenticated internal method allowed: %s %v", method, err)
		}
	}
}
