package host

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"golang.org/x/net/http2"
)

func faviconStreamFixture(t *testing.T, status int, end string) (*ProxyServer, *TunnelConnection, <-chan *pb.ConnectionClose) {
	t.Helper()
	stream := &meteringFixtureStream{}
	tunnel := &TunnelConnection{TunnelID: "api", Stream: stream, pendingRequests: map[string]chan *pb.HttpResponse{}, Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true}}
	cfg := webproxyTestConfig()
	cfg.Domain = "tunn.test"
	server := NewTunnelServer(cfg, nil, nil, nil)
	server.tunnels["api"] = tunnel
	proxy := &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: server}
	closed := make(chan *pb.ConnectionClose, 1)
	stream.hook = func(message *pb.TunnelMessage) error {
		if open := message.GetConnectionOpen(); open != nil {
			id := open.ConnectionId
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: int32(status), Headers: map[string]string{"Content-Length": "100"}}}}})
			if end != "open" {
				tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte("partial")}}})
				tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{ConnectionClose: &pb.ConnectionClose{ConnectionId: id, ErrorMessage: "origin failed"}}})
			}
		}
		if close := message.GetConnectionClose(); close != nil {
			closed <- close
		}
		return nil
	}
	return proxy, tunnel, closed
}

func TestFaviconStreamingFallbackFinishesExchange(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusGone} {
		for _, end := range []string{"open", "partial"} {
			t.Run(http.StatusText(status)+"/"+end, func(t *testing.T) {
				proxy, tunnel, closed := faviconStreamFixture(t, status, end)
				serverConn, clientConn := net.Pipe()
				done := make(chan struct{})
				go func() {
					defer close(done)
					(&http2.Server{}).ServeConn(serverConn, &http2.ServeConnOpts{Handler: http.HandlerFunc(proxy.handleWebProxy)})
				}()
				transport := &http2.Transport{}
				client, err := transport.NewClientConn(clientConn)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { client.Close(); <-done })
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				req, _ := http.NewRequestWithContext(ctx, "GET", "http://api.tunn.test/favicon.ico", nil)
				res, err := client.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				if err != nil || res.StatusCode != 200 || !bytes.Equal(body, faviconBody(t, "api.tunn.test")) {
					t.Fatalf("response=%d bytes=%d error=%v", res.StatusCode, len(body), err)
				}
				select {
				case close := <-closed:
					if close.ErrorMessage != "" {
						t.Fatalf("successful delivery reported failure: %v", close)
					}
				case <-ctx.Done():
					t.Fatal("upstream exchange not closed")
				}
				tunnel.pendingMu.RLock()
				pending := len(tunnel.pendingStreams)
				tunnel.pendingMu.RUnlock()
				if pending != 0 {
					t.Fatalf("pending streams: %d", pending)
				}
			})
		}
	}
}

func TestFaviconStreamingFallbackDeliveryFailure(t *testing.T) {
	proxy, _, closed := faviconStreamFixture(t, http.StatusNotFound, "open")
	req := httptest.NewRequest("GET", "http://api.tunn.test/favicon.ico", nil)
	writer := &faviconResponseWriter{ResponseWriter: &faviconFailedWriter{httptest.NewRecorder()}, request: req, tunnel: &TunnelConnection{}, header: make(http.Header)}
	err := proxy.proxyToLocal(writer, req, "api")
	if !errors.Is(err, io.ErrClosedPipe) || !responseHasStarted(err) {
		t.Fatalf("delivery error=%v", err)
	}
	select {
	case close := <-closed:
		if close.ErrorMessage == "" {
			t.Fatal("delivery failure omitted from close")
		}
	case <-time.After(time.Second):
		t.Fatal("upstream exchange not closed")
	}
}
