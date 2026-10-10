package host

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
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
			if budget == 5 && len(data) != 0 {
				t.Fatal("over-budget frame reached visitor")
			}
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, r)
			if rec.Code != 429 || rec.Header().Get("Tunn-Limit-Reason") != "owner_request_budget" {
				t.Fatalf("%d %v", rec.Code, rec.Header())
			}
		})
	}
}
