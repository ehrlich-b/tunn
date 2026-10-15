package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type webReplaySender struct{ messages []*pb.TunnelMessage }

func (s *webReplaySender) Send(message *pb.TunnelMessage) error {
	s.messages = append(s.messages, message)
	return nil
}

type webReplayTransport func(*http.Request) (*http.Response, error)

func (f webReplayTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestWebInspectorOriginRedirectPolicy(t *testing.T) {
	for _, protocol := range []string{"http", common.HTTPOriginReplayProtocol} {
		t.Run(protocol, func(t *testing.T) {
			calls := 0
			client := &ServeClient{TargetURL: "http://origin.example.test", HTTPTransport: webReplayTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return &http.Response{Request: r, StatusCode: 307, Header: http.Header{"Location": []string{"http://other.example.test/"}}, Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}, nil
				}
				return &http.Response{Request: r, StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}, nil
			})}
			sender := new(webReplaySender)
			client.handleStreamingHTTPRequest(context.Background(), sender, &pb.ConnectionOpen{ConnectionId: "fixture", Protocol: protocol, HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/", Headers: map[string]string{"Host": "public.example.test"}}}, strings.NewReader(""))
			wantCalls, wantStatus := 1, int32(307)
			if calls != wantCalls || len(sender.messages) == 0 || sender.messages[0].GetConnectionAccept().GetHttpResponse().GetStatusCode() != wantStatus {
				t.Fatalf("calls=%d, wanted %d; response messages=%d", calls, wantCalls, len(sender.messages))
			}
		})
	}
}
