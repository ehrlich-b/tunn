package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestOriginRedirectPassthrough(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming", "replay"} {
		for _, status := range []int{301, 302, 307, 308} {
			for _, destination := range []string{"same-origin", "cross-origin"} {
				t.Run(mode+"/"+strconv.Itoa(status)+"/"+destination, func(t *testing.T) {
					var targetRequests atomic.Int32
					target := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						targetRequests.Add(1)
						_, _ = io.WriteString(w, "redirected target")
					})
					location := "/destination?from=origin"
					if destination == "cross-origin" {
						server := httptest.NewServer(target)
						defer server.Close()
						location = server.URL + location
					}
					const body = "origin redirect body\n"
					var originRequests atomic.Int32
					origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != "/redirect" {
							target.ServeHTTP(w, r)
							return
						}
						originRequests.Add(1)
						w.Header().Set("Location", location)
						w.Header().Set("X-Origin", "redirect")
						w.Header().Add("Set-Cookie", "first=1; Path=/")
						w.Header().Add("Set-Cookie", "second=2; Path=/")
						w.WriteHeader(status)
						_, _ = io.WriteString(w, body)
					}))
					defer origin.Close()

					client := &ServeClient{TargetURL: origin.URL}
					sender := &mockEstablishTunnelClient{}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					var gotStatus int32
					var gotHeaders map[string]string
					var gotFields []*pb.HttpHeader
					var gotBody strings.Builder
					if mode == "buffered" {
						client.handleHTTPRequestContext(ctx, sender, &pb.HttpRequest{ConnectionId: "redirect", Method: "GET", Path: "/redirect"})
						response := sender.getSentMsg(0).GetHttpResponse()
						if response == nil || sender.getSentCount() != 1 {
							t.Fatalf("expected one buffered response, got %d messages", sender.getSentCount())
						}
						gotStatus, gotHeaders, gotFields = response.StatusCode, response.Headers, response.HeaderFields
						gotBody.Write(response.Body)
					} else {
						protocol := "http"
						if mode == "replay" {
							protocol = common.HTTPOriginReplayProtocol
						}
						client.handleStreamingHTTPRequest(ctx, sender, &pb.ConnectionOpen{ConnectionId: "redirect", Protocol: protocol, HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/redirect"}}, http.NoBody)
						accept := sender.getSentMsg(0).GetConnectionAccept()
						if !accept.GetSuccess() || accept.GetHttpResponse() == nil {
							t.Fatalf("expected successful streaming response: %v", accept)
						}
						response := accept.HttpResponse
						gotStatus, gotHeaders, gotFields = response.StatusCode, response.Headers, response.HeaderFields
						for i := 1; i < sender.getSentCount()-1; i++ {
							data := sender.getSentMsg(i).GetConnectionData()
							if data == nil {
								t.Fatalf("expected response data: %v", sender.getSentMsg(i))
							}
							gotBody.Write(data.Data)
						}
						if sender.getSentMsg(sender.getSentCount()-1).GetConnectionHalfClose() == nil {
							t.Fatal("stream did not complete successfully")
						}
					}
					if got := targetRequests.Load(); got != 0 {
						t.Errorf("redirected target received %d requests, want zero", got)
					}
					if got := originRequests.Load(); got != 1 {
						t.Errorf("origin received %d requests, want one", got)
					}
					if gotStatus != int32(status) {
						t.Errorf("status = %d, want %d", gotStatus, status)
					}
					if gotHeaders["Location"] != location || gotHeaders["X-Origin"] != "redirect" {
						t.Errorf("redirect headers changed: %v", gotHeaders)
					}
					fields := make(http.Header)
					for _, field := range gotFields {
						fields.Add(field.Name, field.Value)
					}
					if fields.Get("Location") != location || strings.Join(fields.Values("Set-Cookie"), "\n") != "first=1; Path=/\nsecond=2; Path=/" {
						t.Errorf("redirect field lines changed: %v", fields)
					}
					if gotBody.String() != body {
						t.Errorf("body = %q, want %q", gotBody.String(), body)
					}
				})
			}
		}
	}
}
