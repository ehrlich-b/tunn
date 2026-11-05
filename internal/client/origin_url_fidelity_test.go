package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestOriginURLFidelity(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		listener, err := net.Listen(network, map[string]string{"tcp4": "127.0.0.1:0", "tcp6": "[::1]:0"}[network])
		if err != nil {
			t.Fatalf("%s loopback: %v", network, err)
		}
		var calls atomic.Int32
		received := make(chan [2]string, 1)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			received <- [2]string{r.RequestURI, r.Host}
			w.WriteHeader(http.StatusNoContent)
		}))
		server.Listener.Close()
		server.Listener = listener
		server.Start()
		defer server.Close()
		for _, mode := range []string{"buffered", "streaming"} {
			for _, tc := range []struct {
				name, path, want string
				adapter, bad     bool
			}{
				{"escaped", "/a%2Fb/%25/%2b?x=a+b&x=a%20b&p=%25&x=%2F", "/a%2Fb/%25/%2b?x=a+b&x=a%20b&p=%25&x=%2F", false, false},
				{"adapter", "/mcp/a%2Fb?x=1&x=2+3", "/internal/a%2Fb?fixed=%25&x=1&x=2+3", true, false},
				{"empty-query", "/mcp?", "/internal?", true, false},
				{"bad-path", "/bad%2", "", false, true},
				{"bad-query", "/ok?x=%GG", "", false, true},
			} {
				t.Run(network+"/"+mode+"/"+tc.name, func(t *testing.T) {
					client := &ServeClient{TargetURL: server.URL}
					if tc.adapter {
						client.PublicPath, client.UpstreamPath = "/mcp", "/internal"
						if tc.name == "adapter" {
							client.UpstreamRawQuery = "fixed=%25"
						}
					}
					sender := &mockEstablishTunnelClient{}
					before := calls.Load()
					headers := map[string]string{"Host": "public.example"}
					if mode == "buffered" {
						client.handleHTTPRequestContext(context.Background(), sender, &pb.HttpRequest{ConnectionId: "test", Method: "GET", Path: tc.path, Headers: headers})
						response := sender.getSentMsg(0).GetHttpResponse()
						if response == nil || (response.StatusCode == 204) == tc.bad {
							t.Fatalf("response: %v", response)
						}
					} else {
						client.handleStreamingHTTPRequest(context.Background(), sender, &pb.ConnectionOpen{ConnectionId: "test", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: tc.path, Headers: headers}}, io.NopCloser(http.NoBody))
						accept := sender.getSentMsg(0).GetConnectionAccept()
						if accept == nil || accept.Success == tc.bad {
							t.Fatalf("accept: %v", accept)
						}
					}
					if tc.bad {
						if calls.Load() != before {
							t.Fatal("malformed target reached origin")
						}
						return
					}
					got := <-received
					if got != [2]string{tc.want, "public.example"} {
						t.Fatalf("origin received %q, want %q", got, [2]string{tc.want, "public.example"})
					}
				})
			}
		}
	}
}
