package host

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	metpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type accountOperationsResponse struct {
	*httptest.ResponseRecorder
	started chan struct{}
	written chan int
	once    sync.Once
}

func (w *accountOperationsResponse) WriteHeader(code int) {
	w.ResponseRecorder.WriteHeader(code)
	w.once.Do(func() { close(w.started) })
}
func (w *accountOperationsResponse) Flush() { w.ResponseRecorder.Flush() }
func (w *accountOperationsResponse) Write(body []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(body)
	select {
	case w.written <- n:
	default:
	}
	return n, err
}

// Run this again on a pinned combined domains/account-operations head. Pipes
// are disposable local transports, not evidence about a deployed relay.
func TestAccountOperationsCombinedLifecycle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "combined.db")
	db, err := store.OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	local := storage.NewLocalStorage(db)
	a, err := local.FindOrCreateByEmails(ctx, []string{"account-a@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	b, err := local.FindOrCreateByEmails(ctx, []string{"account-b@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := metering.New(db)
	if err != nil {
		t.Fatal(err)
	}
	cfg := securityConfig()
	cfg.Domain = "tunn.test"
	srv := NewTunnelServer(cfg, nil, local.AccountStore(), local)
	p := &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: srv, storage: local, meter: ledger, usageBuffer: NewUsageBuffer(), quotaCache: NewQuotaCache(time.Minute)}
	token := "tunn_ep_combined-local-token"
	digest := sha256.Sum256([]byte(token))
	grantToken := "tunn_gr_combined-local-token"
	grantDigest := sha256.Sum256([]byte(grantToken))
	if _, err = ledger.CreateGrant(ctx, &metpb.Grant{Owner: a.ID, Endpoint: "a-http", TokenSha256: grantDigest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	type active struct {
		tunnel *TunnelConnection
		id     string
		done   chan struct{}
		writer *accountOperationsResponse
		peer   net.Conn
	}
	streams := map[string]*active{}
	for _, kind := range []string{"a-http", "a-connect", "a-websocket", "b-http"} {
		owner := a
		if kind == "b-http" {
			owner = b
		}
		stream := &meteringFixtureStream{}
		tunnel := &TunnelConnection{TunnelID: kind, AccountID: owner.ID, CreatorEmail: owner.PrimaryEmail, Stream: stream, Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityConnectionStreamV1: true, common.CapabilityWebSocketV1: true}, pendingRequests: make(map[string]chan *pb.HttpResponse), pendingStreams: make(map[string]*pendingConnection)}
		if owner.ID == a.ID {
			tunnel.updateAccessTokenDigest(digest[:])
		}
		if kind == "a-connect" {
			tunnel.EndpointProtocol = "tcp"
		}
		srv.tunnels[kind] = tunnel
		opened := make(chan string, 1)
		stream.hook = func(msg *pb.TunnelMessage) error {
			if open := msg.GetConnectionOpen(); open != nil {
				head := &pb.HttpResponseHead{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/event-stream"}}
				if open.Protocol == "websocket" {
					head.StatusCode = 101
					head.Headers = map[string]string{"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Accept": common.WebSocketAccept("dGhlIHNhbXBsZSBub25jZQ==")}
				}
				tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: head}}})
				opened <- open.ConnectionId
			}
			return nil
		}
		r := httptest.NewRequest("GET", "https://"+kind+".tunn.test/", nil)
		if owner.ID == a.ID {
			r.Header.Set("Tunn-Authorization", "Bearer "+token)
		}
		writer := &accountOperationsResponse{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), written: make(chan int, 4)}
		var responseWriter http.ResponseWriter = writer
		var peer net.Conn
		if kind == "a-connect" {
			reader, bodyWriter := io.Pipe()
			defer func() { _ = bodyWriter.Close() }()
			r.Method = "CONNECT"
			r.URL.Path = common.TCPConnectPath
			r.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
			r.Body = reader
		}
		if kind == "a-websocket" {
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			r.Header.Set("Sec-WebSocket-Version", "13")
			ingress, remote := net.Pipe()
			peer = remote
			defer func() { _ = remote.Close() }()
			responseWriter = cookieFixtureHijacker{ResponseRecorder: writer.ResponseRecorder, conn: ingress}
		}
		done := make(chan struct{})
		go func() { defer close(done); p.proxyToLocal(responseWriter, r, kind) }()
		var id string
		select {
		case id = <-opened:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s did not open", kind)
		}
		if peer != nil {
			_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
			response, err := http.ReadResponse(bufio.NewReader(peer), r)
			if err != nil || response.StatusCode != 101 {
				t.Fatalf("WS acceptance %v %v", response, err)
			}
			_ = peer.SetReadDeadline(time.Time{})
		} else {
			select {
			case <-writer.started:
			case <-time.After(3 * time.Second):
				t.Fatalf("%s was not established", kind)
			}
		}
		streams[kind] = &active{tunnel, id, done, writer, peer}
	}
	// Demonstrate actual response traffic before stopping the idle wait. This
	// exercises established streams, rather than only their opening handshakes.
	transferred := int64(0)
	for _, kind := range []string{"a-http", "a-connect", "a-websocket"} {
		connection := streams[kind]
		payload := []byte("A payload")
		if kind == "a-websocket" {
			payload = append([]byte{0x81, byte(len(payload))}, payload...)
		}
		connection.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: connection.id, Data: payload}}})
		if connection.peer != nil {
			_ = connection.peer.SetReadDeadline(time.Now().Add(3 * time.Second))
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(connection.peer, got); err != nil || string(got) != string(payload) {
				t.Fatal("WS transfer", got, err)
			}
			_ = connection.peer.SetReadDeadline(time.Time{})
		} else {
			select {
			case n := <-connection.writer.written:
				if n != len(payload) {
					t.Fatal("partial transfer", n)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("response did not transfer", kind)
			}
		}
		transferred += int64(len(payload))
	}
	if err = local.RecordUsage(ctx, a.ID, 123); err != nil {
		t.Fatal(err)
	}
	admin := accountOperationsAdmin(t, a.ID)
	if _, err = local.OperationsStore().Transition(ctx, admin, a.ID, "suspended", "combined fixture hold", 0); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(6 * time.Second)
	for _, kind := range []string{"a-http", "a-connect", "a-websocket"} {
		select {
		case <-streams[kind].done:
		case <-deadline:
			t.Fatalf("established %s survived suspension", kind)
		}
	}
	select {
	case <-streams["b-http"].done:
		t.Fatal("B was terminated by A suspension")
	default:
	}
	other := streams["b-http"]
	other.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: other.id, Data: []byte("B continues")}}})
	other.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: other.id}}})
	select {
	case <-other.done:
	case <-time.After(3 * time.Second):
		t.Fatal("B did not complete")
	}
	if other.writer.Body.String() != "B continues" {
		t.Fatal(other.writer.Body.String())
	}
	if err = local.UpdatePlan(ctx, a.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	c, err := local.FindOrCreateByEmails(ctx, []string{"merged@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = local.RecordUsage(ctx, c.ID, 50); err != nil {
		t.Fatal(err)
	}
	merged, err := local.FindOrCreateByEmails(ctx, []string{a.PrimaryEmail, c.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	local = storage.NewLocalStorage(db)
	p.storage = local
	ledger, err = metering.New(db)
	if err != nil {
		t.Fatal(err)
	}
	p.meter = ledger
	status, err := local.LookupAccountStatus(ctx, a.ID)
	if err != nil || status.State != "suspended" || status.AccountID != merged.ID {
		t.Fatal(status, err)
	}
	for _, credential := range []string{relayJWT(t, p, a.PrimaryEmail), token, grantToken} {
		r := httptest.NewRequest("GET", "https://a-http.tunn.test/", nil)
		r.Header.Set("Tunn-Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		p.proxyToLocal(w, r, "a-http")
		if w.Code != 403 {
			t.Fatal("restart admission", w.Code, w.Body.String())
		}
	}
	reconnect := &mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}
	reconnect.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "reconnect", TunnelKey: cfg.WellKnownKey, AuthToken: relayJWT(t, p, a.PrimaryEmail), TargetUrl: "http"}}}
	close(reconnect.recvQueue)
	srv.storage = local
	if err = srv.EstablishTunnel(reconnect); err == nil {
		t.Fatal("restart allowed suspended publisher")
	}
	if _, err = local.OperationsStore().Transition(ctx, accountOperationsAdmin(t, merged.ID), merged.ID, "active", "combined fixture reviewed", status.Version); err != nil {
		t.Fatal(err)
	}
	aHTTP := streams["a-http"].tunnel
	aHTTP.Capabilities = nil
	aHTTP.Stream = &meteringFixtureStream{hook: func(msg *pb.TunnelMessage) error {
		if req := msg.GetHttpRequest(); req != nil {
			aHTTP.pendingMu.RLock()
			ch := aHTTP.pendingRequests[req.ConnectionId]
			aHTTP.pendingMu.RUnlock()
			ch <- &pb.HttpResponse{ConnectionId: req.ConnectionId, StatusCode: 200, Body: []byte("resumed")}
		}
		return nil
	}}
	r := httptest.NewRequest("GET", "https://a-http.tunn.test/", nil)
	r.Header.Set("Tunn-Authorization", "Bearer "+grantToken)
	w := httptest.NewRecorder()
	p.proxyToLocal(w, r, "a-http")
	if w.Code != 200 || w.Body.String() != "resumed" {
		t.Fatal("resume", w.Code, w.Body.String())
	}
	if usage, err := local.GetMonthlyUsage(ctx, merged.ID); err != nil || usage != 173+transferred+int64(len("resumed")) {
		t.Fatal("usage lost", usage, err)
	}
	if exported, err := ledger.Export(ctx, &metpb.ExportRequest{Owner: merged.ID}); err != nil || exported.OwnerUsage.AdmittedRequests != 4 {
		t.Fatalf("ledger lost admissions %+v %v", exported, err)
	}
	// The public intake route cannot select or moderate another account.
	report := httptest.NewRequest("POST", "https://tunn.test/api/reports", strings.NewReader(fmt.Sprintf(`{"category":"abuse","endpoint":"a-http","account_id":%q}`, b.ID)))
	report.Header.Set("Authorization", "Bearer "+relayJWT(t, p, a.PrimaryEmail))
	rec := httptest.NewRecorder()
	p.handleReportIntake(rec, report)
	if rec.Code != 400 {
		t.Fatal("client account ID trusted", rec.Code)
	}
}
