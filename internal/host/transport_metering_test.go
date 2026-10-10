package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/store"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

type pipeUpgradeWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *pipeUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func transportLedger(t *testing.T, p *ProxyServer, requests, bytes int64) *metering.Store {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ledger, err := metering.New(db, metering.WithOwnerBudgets(requests, bytes))
	if err != nil {
		t.Fatal(err)
	}
	p.meter = ledger
	return ledger
}

func TestTransportTCPAndMCPActiveCutoff(t *testing.T) {
	for _, protocol := range []string{"tcp", "mcp"} {
		t.Run(protocol, func(t *testing.T) {
			p, tunnel, _, stream := meteringRelay(t, true, "")
			ledger := transportLedger(t, p, 10, 5)
			r := relayRequest(relayJWT(t, p, "alice@example.com"), "abc")
			if protocol == "tcp" {
				tunnel.EndpointProtocol = "tcp"
				r.Method = http.MethodConnect
				r.URL.Path = common.TCPConnectPath
				r.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
			} else {
				r.URL.Path = "/mcp"
			}
			stream.hook = func(msg *pb.TunnelMessage) error {
				if end := msg.GetConnectionHalfClose(); end != nil {
					accept := &pb.ConnectionAccept{ConnectionId: end.ConnectionId, Success: true}
					if protocol != "tcp" {
						accept.HttpResponse = &pb.HttpResponseHead{StatusCode: 200}
					}
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: accept}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: end.ConnectionId, Data: []byte("abcdef")}}})
				}
				return nil
			}
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, r)
			if rec.Code != 200 || rec.Body.String() != "ab" || rec.Result().Trailer.Get("Tunn-Limit-Reason") != "owner_byte_budget" {
				t.Fatalf("%d %q %v", rec.Code, rec.Body, rec.Result().Trailer)
			}
			out := relayExport(t, ledger)
			if out.OwnerUsage.TotalBytes != 5 || out.OwnerUsage.AdmittedRequests != 1 {
				t.Fatal(out)
			}
			rec = httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, r.Clone(context.Background()))
			if rec.Code != 429 {
				t.Fatal(rec.Code)
			}
		})
	}
}

func TestWebSocketFramesUseAccountLedger(t *testing.T) {
	for _, budget := range []int64{5, 14} {
		t.Run(strings.Repeat("x", int(budget)), func(t *testing.T) {
			p, tunnel, _, stream := meteringRelay(t, false, "")
			ledger := transportLedger(t, p, 1, budget)
			tunnel.Capabilities = map[string]bool{common.CapabilityWebSocketV1: true}
			r := relayRequest(relayJWT(t, p, "alice@example.com"), "")
			r.Method = "GET"
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Connection", "upgrade")
			r.Header.Set("Sec-WebSocket-Version", "13")
			r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			stream.hook = func(msg *pb.TunnelMessage) error {
				if open := msg.GetConnectionOpen(); open != nil {
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 101, Headers: map[string]string{"Upgrade": "websocket", "Connection": "upgrade", "Sec-WebSocket-Accept": common.WebSocketAccept(r.Header.Get("Sec-WebSocket-Key"))}}}}})
				}
				if data := msg.GetConnectionData(); data != nil {
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: data.ConnectionId, Data: []byte{0x82, 4, 't', 'e', 's', 't'}}}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: data.ConnectionId}}})
				}
				return nil
			}
			serverConn, clientConn := net.Pipe()
			defer clientConn.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				p.createHandler().ServeHTTP(&pipeUpgradeWriter{httptest.NewRecorder(), serverConn}, r)
			}()
			reader := bufio.NewReader(clientConn)
			resp, err := http.ReadResponse(reader, r)
			if err != nil || resp.StatusCode != 101 {
				t.Fatalf("%v %v", resp, err)
			}
			if _, err := clientConn.Write([]byte{0x82, 0x82, 1, 2, 3, 4, 'o' ^ 1, 'k' ^ 2}); err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(reader)
			if budget == 14 && (err != nil || string(data) != string([]byte{0x82, 4, 't', 'e', 's', 't'})) {
				t.Fatalf("%v %v", data, err)
			}
			<-done
			out := relayExport(t, ledger)
			if out.OwnerUsage.TotalBytes != budget || out.OwnerUsage.AdmittedRequests != 1 {
				t.Fatal(out)
			}
			if budget == 5 {
				frame, err := fixtureReadFrame(strings.NewReader(string(data)), false)
				if err != nil || frame.opcode != 8 || string(frame.payload[2:]) != "owner_byte_budget" {
					t.Fatalf("missing policy close: %v %v", frame, err)
				}
			}
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, r)
			if rec.Code != 429 || rec.Header().Get("Tunn-Limit-Reason") != "owner_request_budget" {
				t.Fatalf("%d %v", rec.Code, rec.Header())
			}
		})
	}
}

func TestAccountUsageViewIncludesActiveStreamBytes(t *testing.T) {
	p, tunnel, _, _ := meteringRelay(t, false, "")
	ledger := transportLedger(t, p, 10, 100)
	session := newIngressMeter(p, tunnel)
	rec := httptest.NewRecorder()
	if !session.admit(context.Background(), rec, relayRequest("", "")) {
		t.Fatal(rec.Body)
	}
	if _, err := session.charge(context.Background(), true, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := session.charge(context.Background(), false, 6); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://tunn.test/account", nil)
	r.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, p, "owner@example.com")})
	rec = httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, r)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "10 B of 1.0 GB") || !strings.Contains(rec.Body.String(), "1 of 100000 requests admitted") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	out := relayExport(t, ledger)
	if out.OwnerUsage.TotalBytes != 10 || out.Events[0].Finished {
		t.Fatal(out)
	}
}

type concurrentReservationBackend struct {
	metering.Backend
	onProbe func()
}

func (b *concurrentReservationBackend) Charge(ctx context.Context, r *meterpb.ChargeRequest) (*meterpb.Decision, error) {
	d, err := b.Backend.Charge(ctx, r)
	if err == nil && r.RequestBytes == 0 && r.ResponseBytes == 0 && b.onProbe != nil {
		f := b.onProbe
		b.onProbe = nil
		f()
	}
	return d, err
}
func TestBufferedResponseReservesBeforeHeadersWhenBudgetChanges(t *testing.T) {
	p, tunnel, _, _ := meteringRelay(t, false, "data")
	ledger := transportLedger(t, p, 10, 5)
	other := newIngressMeter(p, tunnel)
	other.event.Endpoint = "other"
	if !other.admit(context.Background(), httptest.NewRecorder(), relayRequest("", "")) {
		t.Fatal("admission")
	}
	backend := &concurrentReservationBackend{Backend: ledger, onProbe: func() {
		if _, err := other.charge(context.Background(), true, 3); err != nil {
			t.Fatal(err)
		}
	}}
	p.meter = backend
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, relayRequest(relayJWT(t, p, "alice@example.com"), ""))
	if rec.Code != 429 || rec.Header().Get("Tunn-Limit-Reason") != "owner_byte_budget" || rec.Body.String() == "data" {
		t.Fatalf("race committed success: %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	out, err := ledger.Export(context.Background(), &meterpb.ExportRequest{Owner: tunnel.AccountID})
	if err != nil || out.OwnerUsage.TotalBytes != 3 {
		t.Fatalf("unused reservation not reconciled %v %v", out, err)
	}
}

func TestWebSocketBoundaryTracksSplitHeadersAndPayloads(t *testing.T) {
	var b webSocketBoundary
	frame := fixtureFrame(2, true, false, []byte(strings.Repeat("x", 130)))
	for i, c := range frame {
		b.consume([]byte{c})
		if b.atBoundary() != (i == len(frame)-1) {
			t.Fatalf("incorrect frame boundary at %d", i)
		}
	}
	b.consume(append(fixtureFrame(1, true, false, []byte("one")), fixtureFrame(1, true, false, []byte("two"))...))
	if !b.atBoundary() {
		t.Fatal("multiple-frame chunk lost boundary")
	}
}

func TestMeterIdleStreamStopsOnExhaustionAndAuthorityLoss(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(fmt.Sprint(unavailable), func(t *testing.T) {
			p, tunnel, _, _ := meteringRelay(t, false, "")
			ledger := transportLedger(t, p, 10, 3)
			session := newIngressMeter(p, tunnel)
			if !session.admit(context.Background(), httptest.NewRecorder(), relayRequest("", "")) {
				t.Fatal("admission")
			}
			if unavailable {
				session.backend = &metering.Remote{Connection: func() *grpc.ClientConn { return nil }}
			} else {
				other := newIngressMeter(p, tunnel)
				if !other.admit(context.Background(), httptest.NewRecorder(), relayRequest("", "")) {
					t.Fatal("admission")
				}
				if _, err := other.charge(context.Background(), true, 3); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			done := make(chan struct{})
			go func() { defer close(done); session.watchEvery(ctx, cancel, 10*time.Millisecond) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("idle stream was not terminated")
			}
			cause := context.Cause(ctx)
			if unavailable {
				var failure *meterUnavailableError
				if !errors.As(cause, &failure) {
					t.Fatal(cause)
				}
			} else {
				var limit *ingressLimitError
				if !errors.As(cause, &limit) || limit.decision.Reason != "owner_byte_budget" {
					t.Fatal(cause)
				}
			}
			out := relayExport(t, ledger)
			if unavailable && out.OwnerUsage.TotalBytes != 0 {
				t.Fatal(out)
			}
		})
	}
}

func TestAccountPlanUpgradeOverridesPublisherSnapshotAndOldMirror(t *testing.T) {
	p, tunnel, _, _ := meteringRelay(t, false, "ok")
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO accounts(id,primary_email,plan,created_at) VALUES(?,?,'pro',1);`, tunnel.AccountID, tunnel.CreatorEmail); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO account_usage(account_id,month,bytes_used) VALUES(?,?,?)`, tunnel.AccountID, time.Now().UTC().Format("2006-01"), FreeQuotaBytes); err != nil {
		t.Fatal(err)
	}
	ledger, err := metering.New(db, metering.WithAccountPlans())
	if err != nil {
		t.Fatal(err)
	}
	p.meter, p.planMeter = ledger, true
	tunnel.Plan = "free"
	p.storage.(*meteringFixtureStorage).usage[tunnel.AccountID] = FreeQuotaBytes
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, relayRequest(relayJWT(t, p, "alice@example.com"), ""))
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("upgrade blocked by old plan: %d %s", rec.Code, rec.Body)
	}
	if _, err := db.Exec(`UPDATE accounts SET plan='free'`); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, relayRequest(relayJWT(t, p, "alice@example.com"), ""))
	if rec.Code != 429 || rec.Header().Get("Tunn-Limit-Reason") != "owner_byte_budget" {
		t.Fatalf("downgrade allowed: %d %v", rec.Code, rec.Header())
	}
}
