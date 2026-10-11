package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type fidelityNoBody struct{ reads, closes int }

func (b *fidelityNoBody) Read([]byte) (int, error) { b.reads++; return 0, io.ErrUnexpectedEOF }
func (b *fidelityNoBody) Close() error             { b.closes++; return nil }

func TestHTTPFidelityNoBodyRead(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming"} {
		for _, c := range []struct {
			method string
			status int
		}{{"HEAD", 200}, {"GET", 204}, {"GET", 304}} {
			t.Run(mode+"/"+http.StatusText(c.status)+"/"+c.method, func(t *testing.T) {
				body := &fidelityNoBody{}
				client := &ServeClient{TargetURL: "http://fixture.invalid", HTTPTransport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: c.status, Header: http.Header{"Content-Length": {"7"}}, Body: body, ContentLength: 7}, nil
				})}
				sender := &mockEstablishTunnelClient{}
				if mode == "buffered" {
					client.handleHTTPRequestContext(context.Background(), sender, &pb.HttpRequest{ConnectionId: "bodyless", Method: c.method, Path: "/"})
				} else {
					client.handleStreamingHTTPRequest(context.Background(), sender, &pb.ConnectionOpen{ConnectionId: "bodyless", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: c.method, Path: "/"}}, strings.NewReader(""))
				}
				if body.reads != 0 || body.closes != 1 {
					t.Fatalf("body reads=%d closes=%d", body.reads, body.closes)
				}
				if mode == "buffered" {
					got := sender.getSentMsg(0).GetHttpResponse()
					if got.StatusCode != int32(c.status) || len(got.Body) != 0 {
						t.Fatalf("buffered: %v", got)
					}
				} else {
					if sender.getSentCount() != 2 || sender.getSentMsg(1).GetConnectionHalfClose() == nil {
						t.Fatalf("bodyless stream: %d frames", sender.getSentCount())
					}
				}
			})
		}
	}
}

type fidelityFailingBody struct{ closed int }

func (b *fidelityFailingBody) Read(dst []byte) (int, error) {
	return copy(dst, "abc"), io.ErrUnexpectedEOF
}
func (b *fidelityFailingBody) Close() error { b.closed++; return nil }

func TestHTTPFidelityBytesWithReadError(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			body := &fidelityFailingBody{}
			client := &ServeClient{TargetURL: "http://fixture.invalid", HTTPTransport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 202, Header: make(http.Header), Body: body, ContentLength: -1}, nil
			})}
			sender := &mockEstablishTunnelClient{}
			if mode == "buffered" {
				client.handleHTTPRequestContext(context.Background(), sender, &pb.HttpRequest{ConnectionId: "error", Method: "GET", Path: "/"})
				if sender.getSentCount() != 1 || sender.getSentMsg(0).GetHttpResponse().StatusCode != 502 {
					t.Fatal("buffered error changed to success")
				}
			} else {
				client.handleStreamingHTTPRequest(context.Background(), sender, &pb.ConnectionOpen{ConnectionId: "error", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/"}}, strings.NewReader(""))
				if sender.getSentCount() != 3 || sender.getSentMsg(0).GetConnectionAccept().HttpResponse.StatusCode != 202 || string(sender.getSentMsg(1).GetConnectionData().Data) != "abc" || sender.getSentMsg(2).GetConnectionClose().ErrorMessage == "" {
					t.Fatal("bytes/error did not retain final metadata and fail terminal frame")
				}
			}
			if body.closed != 1 {
				t.Fatalf("body closed %d times", body.closed)
			}
		})
	}
}
