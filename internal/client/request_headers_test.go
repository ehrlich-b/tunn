package client

import (
	"context"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRequestHeadersRejectedBeforeOrigin(t *testing.T) {
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer origin.Close()
	s := &ServeClient{TargetURL: origin.URL}
	for _, fields := range [][]*pb.HttpHeader{
		{{Name: "Host", Value: "a"}, {Name: "host", Value: "b"}},
		{{Name: "Authorization", Value: "a"}, {Name: "authorization", Value: "b"}},
		{{Name: "Content-Length", Value: "0"}, {Name: "content-length", Value: "0"}},
		{{Name: "Content-Length", Value: "0, 0"}},
		{{Name: "Content-Length", Value: "0"}, {Name: "Transfer-Encoding", Value: "chunked"}},
		{{Name: "X-App", Value: "bad\r\nInjected: value"}},
	} {
		sender := &mockEstablishTunnelClient{}
		s.handleHttpRequest(sender, &pb.HttpRequest{ConnectionId: "buffered", Method: "GET", Path: "/", HeaderFields: fields})
		s.handleStreamingHTTPRequest(context.Background(), sender, &pb.ConnectionOpen{ConnectionId: "stream", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/", HeaderFields: fields}}, strings.NewReader(""))
		s.handleWebSocket(context.Background(), sender, &pb.ConnectionOpen{ConnectionId: "ws", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/", HeaderFields: fields}}, strings.NewReader(""))
	}
	if calls.Load() != 0 {
		t.Fatalf("origin received %d malformed requests", calls.Load())
	}
}
