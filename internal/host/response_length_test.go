package host

import (
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestHTTPFidelityConsumerContentLengths(t *testing.T) {
	for _, fixture := range []struct{ name, body, length string }{{"exact", "abc", "3"}, {"short", "ab", "3"}, {"long", "abcd", "3"}, {"absent", "abc", ""}} {
		for _, mode := range []string{"buffered", "streaming"} {
			t.Run(fixture.name+"/"+mode, func(t *testing.T) {
				stream := &meteringFixtureStream{}
				tunnel := &TunnelConnection{TunnelID: "api", Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse), Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: mode == "streaming"}}
				cfg := webproxyTestConfig()
				cfg.Domain = "tunn.test"
				server := NewTunnelServer(cfg, nil, nil, nil)
				server.tunnels["api"] = tunnel
				proxy := &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: server}
				var fields []*pb.HttpHeader
				if fixture.length != "" {
					fields = []*pb.HttpHeader{{Name: "Content-Length", Value: fixture.length}}
				}
				stream.hook = func(message *pb.TunnelMessage) error {
					if request := message.GetHttpRequest(); request != nil {
						tunnel.pendingMu.RLock()
						response := tunnel.pendingRequests[request.ConnectionId]
						tunnel.pendingMu.RUnlock()
						response <- &pb.HttpResponse{StatusCode: 202, HeaderFields: fields, Body: []byte(fixture.body)}
					}
					if open := message.GetConnectionOpen(); open != nil {
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 202, HeaderFields: fields}}}})
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte(fixture.body)}}})
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId}}})
					}
					return nil
				}
				response, body, readErr := responseFailureMemoryResponse(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxy.proxyToLocal(w, r, "api") }))
				mismatch := fixture.name == "short" || fixture.name == "long"
				if mismatch {
					if !errors.Is(readErr, io.ErrUnexpectedEOF) && !errors.Is(readErr, io.EOF) {
						t.Fatalf("incomplete %s response looked successful: %q %v", fixture.name, body, readErr)
					}
				} else if readErr != nil || response == nil || response.StatusCode != 202 || body != fixture.body {
					t.Fatalf("complete response=%v %q %v", response, body, readErr)
				}
				t.Logf("declared=%q sent=%d read=%d error=%v", fixture.length, len(fixture.body), len(body), readErr)
			})
		}
	}
}
