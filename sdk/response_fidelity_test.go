package tunn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"reflect"
	"sync"

	"github.com/ehrlich-b/tunn/internal/common"
	"strings"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// observeResponse extends the existing memory TLS/gRPC fixture, keeping the
// real SDK HTTP pipe and client serializer in both modes.
type observedResponse struct {
	trailers     []*pb.HttpHeader
	trailerNames []string
	rejection    string
	status       int
	headers      map[string]string
	fields       []*pb.HttpHeader
	body         string
	frames       []*pb.TunnelMessage
	err          error
}

func observeResponse(t *testing.T, mode, method string, handler http.Handler, relayTrailers ...bool) observedResponse {
	t.Helper()
	result := make(chan observedResponse, 1)
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) (err error) {
		var got observedResponse
		delivered := false
		defer func() {
			if err != nil && !delivered {
				got.err = err
				delivered = true
				result <- got
			}
		}()
		reg, err := registration(stream)
		if err != nil {
			return err
		}
		if len(relayTrailers) > 0 && !relayTrailers[0] {
			err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://" + reg.TunnelId + ".sdk.test", Capabilities: []string{"http-stream-v1", "connection-stream-v1", "websocket-v1"}}}})
		} else {
			err = acceptRegistration(stream, reg)
		}
		if err != nil {
			return err
		}
		if mode == "buffered" {
			err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: "fidelity", Method: method, Path: "/"}}})
		} else {
			err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: &pb.ConnectionOpen{ConnectionId: "fidelity", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: method, Path: "/"}}}})
			if err == nil {
				err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: "fidelity"}}})
			}
		}
		if err != nil {
			return err
		}
		for {
			message, receiveErr := stream.Recv()
			if receiveErr != nil {
				return receiveErr
			}
			got.frames = append(got.frames, message)
			switch {
			case message.GetHttpResponse() != nil:
				response := message.GetHttpResponse()
				got.status, got.headers, got.body = int(response.StatusCode), response.Headers, string(response.Body)
				got.fields = response.HeaderFields
				got.trailers, got.trailerNames = response.Trailers, response.TrailerNames
				delivered = true
				result <- got
				return drainUntilCanceled(stream)
			case message.GetConnectionAccept() != nil:
				accept := message.GetConnectionAccept()
				if !accept.Success {
					got.rejection = accept.ErrorMessage
					delivered = true
					result <- got
					return drainUntilCanceled(stream)
				}
				if accept.HttpResponse == nil {
					return fmt.Errorf("missing response metadata")
				}
				got.status, got.headers = int(accept.HttpResponse.StatusCode), accept.HttpResponse.Headers
				got.fields = accept.HttpResponse.HeaderFields
				got.trailerNames = accept.HttpResponse.TrailerNames
			case message.GetConnectionData() != nil:
				got.body += string(message.GetConnectionData().Data)
			case message.GetConnectionHalfClose() != nil, message.GetConnectionClose() != nil:
				if terminal := message.GetConnectionHalfClose(); terminal != nil {
					got.trailers = terminal.Trailers
				}
				delivered = true
				result <- got
				return drainUntilCanceled(stream)
			}
		}
	})
	o := fixtureOptions()
	o.Origin, o.TLSConfig = "http://sdk-handler.invalid", tlsConfig
	tunnel := startFixtureTunnel(t, context.Background(), o, dial, testHandlerOrigin(handler))
	var got observedResponse
	select {
	case got = <-result:
	case <-time.After(3 * time.Second):
		t.Fatal("response did not terminate")
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	return got
}

// This independent reference bypasses the tunnel and uses ordinary net/http
// semantics over a private handler pipe, including HEAD and bodyless statuses.
func directHandlerResponse(t *testing.T, method string, handler http.Handler, traces ...*httptrace.ClientTrace) (*http.Response, string) {
	t.Helper()
	origin := testHandlerOrigin(handler)
	origin.start(context.Background())
	defer origin.close()
	transport := &http.Transport{DialContext: origin.dial}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequest(method, "http://sdk-handler.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(traces) > 0 {
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), traces[0]))
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, string(body)
}

func fidelityCookieHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("X-Repeat", "one,two")
	w.Header().Add("X-Repeat", "three")
	http.SetCookie(w, &http.Cookie{Name: "first", Value: "one,fragment=two", Path: "/", Expires: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)})
	http.SetCookie(w, &http.Cookie{Name: "second", Value: "three", Path: "/"})
	w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(w, "response bytes")
}

func TestHTTPFidelityLegacyHeaderLoss(t *testing.T) {
	handler := http.HandlerFunc(fidelityCookieHandler)
	reference, body := directHandlerResponse(t, http.MethodGet, handler)
	if len(reference.Header.Values("X-Repeat")) != 2 || len(reference.Cookies()) != 2 {
		t.Fatal("reference lacks repeated fields")
	}
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			got := observeResponse(t, mode, http.MethodGet, handler)
			if got.status != reference.StatusCode || got.body != body {
				t.Fatalf("status/body: %d %q", got.status, got.body)
			}
			if got.headers["X-Repeat"] != strings.Join(reference.Header.Values("X-Repeat"), ", ") || got.headers["Set-Cookie"] != strings.Join(reference.Header.Values("Set-Cookie"), ", ") {
				t.Fatalf("legacy map: %v", got.headers)
			}
			t.Logf("legacy map collapses 2/2 repeated fields into one value each; body=%d bytes", len(got.body))
		})
	}
}

func TestHTTPFidelityRepeatedFields(t *testing.T) {
	handler := http.HandlerFunc(fidelityCookieHandler)
	reference, body := directHandlerResponse(t, http.MethodGet, handler)
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			got := observeResponse(t, mode, http.MethodGet, handler)
			headers := common.DecodeHTTPResponseHeaders(got.headers, got.fields)
			for _, name := range []string{"X-Repeat", "Set-Cookie"} {
				if !reflect.DeepEqual(headers.Values(name), reference.Header.Values(name)) {
					t.Fatalf("%s: %v, want %v", name, headers.Values(name), reference.Header.Values(name))
				}
			}
			if got.body != body {
				t.Fatalf("body: %q", got.body)
			}
			t.Logf("preserved 2/2 cookies, 2/2 ordinary values, %d body bytes", len(got.body))
		})
	}
}

func TestHTTPFidelityBodySemantics(t *testing.T) {
	cases := []struct {
		name, method, length, body string
		status                     int
		flush                      bool
	}{
		{"known", "GET", "3", "abc", 200, false},
		{"unknown", "GET", "", "abc", 200, true},
		{"zero", "GET", "0", "", 200, true},
		{"empty", "GET", "", "", 200, false},
		{"status-only", "GET", "", "", 202, false},
		{"head", "HEAD", "3", "abc", 200, false},
		{"no-content", "GET", "", "abc", 204, false},
		{"not-modified", "GET", "", "abc", 304, false},
	}
	for _, c := range cases {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c.length != "" {
				w.Header().Set("Content-Length", c.length)
			}
			w.WriteHeader(c.status)
			if c.flush {
				w.(http.Flusher).Flush()
			}
			if c.body != "" {
				_, _ = io.WriteString(w, c.body)
			}
		})
		reference, body := directHandlerResponse(t, c.method, handler)
		for _, mode := range []string{"buffered", "streaming"} {
			t.Run(c.name+"/"+mode, func(t *testing.T) {
				got := observeResponse(t, mode, c.method, handler)
				headers := common.DecodeHTTPResponseHeaders(got.headers, got.fields)
				if got.status != reference.StatusCode || got.body != body || !reflect.DeepEqual(headers.Values("Content-Length"), reference.Header.Values("Content-Length")) {
					t.Fatalf("got %d %q CL=%v; want %d %q CL=%v", got.status, got.body, headers.Values("Content-Length"), reference.StatusCode, body, reference.Header.Values("Content-Length"))
				}
				terminal := 0
				for _, frame := range got.frames {
					if frame.GetHttpResponse() != nil || frame.GetConnectionHalfClose() != nil || frame.GetConnectionClose() != nil {
						terminal++
					}
				}
				if terminal != 1 {
					t.Fatalf("terminal frames: %d", terminal)
				}
				t.Logf("body=%d bytes, Content-Length=%q, terminal frames=%d", len(got.body), headers.Get("Content-Length"), terminal)
			})
		}
	}
}

func fidelityTrailerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Trailer", "X-End")
	w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(w, "prefix")
	w.(http.Flusher).Flush()
	w.Header().Add("X-End", "one,two")
	w.Header().Add("X-End", "three")
}

func TestHTTPFidelityTrailers(t *testing.T) {
	handler := http.HandlerFunc(fidelityTrailerHandler)
	reference, body := directHandlerResponse(t, "GET", handler)
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			got := observeResponse(t, mode, "GET", handler)
			trailers := common.DecodeHTTPResponseHeaders(nil, got.trailers)
			if got.body != body || !reflect.DeepEqual(trailers, reference.Trailer) || !reflect.DeepEqual(got.trailerNames, []string{"X-End"}) {
				t.Fatalf("response: body=%q names=%v trailers=%v reference=%v", got.body, got.trailerNames, trailers, reference.Trailer)
			}
			terminal := 0
			for _, frame := range got.frames {
				if frame.GetHttpResponse() != nil || frame.GetConnectionHalfClose() != nil {
					terminal++
				}
				if frame.GetConnectionClose() != nil {
					t.Fatal("trailers ended with an error close")
				}
			}
			if terminal != 1 {
				t.Fatalf("terminal frame count: %d", terminal)
			}
			t.Logf("delivered %d/2 trailer values, %d body bytes, %d terminal frame", len(got.trailers), len(got.body), terminal)
		})
		t.Run(mode+"/old-relay", func(t *testing.T) {
			got := observeResponse(t, mode, "GET", handler, false)
			if mode == "buffered" {
				if got.status != 502 || !strings.Contains(got.body, "upgraded relay") {
					t.Fatalf("unsupported trailers: %d %q", got.status, got.body)
				}
			} else if !strings.Contains(got.rejection, "upgraded relay") || got.body != "" {
				t.Fatalf("unsupported trailers: %+v", got)
			}
		})
	}
}

func TestHTTPFidelityFlushedPrefix(t *testing.T) {
	prefix := make(chan string, 1)
	release := make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "prefix")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "suffix")
		case <-r.Context().Done():
		}
	})
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
		reg, err := registration(stream)
		if err != nil {
			return err
		}
		if err = acceptRegistration(stream, reg); err != nil {
			return err
		}
		if err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: &pb.ConnectionOpen{ConnectionId: "flush", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/"}}}}); err != nil {
			return err
		}
		if err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: "flush"}}}); err != nil {
			return err
		}
		for {
			message, err := stream.Recv()
			if err != nil {
				return err
			}
			if chunk := message.GetConnectionData(); chunk != nil {
				prefix <- string(chunk.Data)
				return drainUntilCanceled(stream)
			}
		}
	})
	o := fixtureOptions()
	o.Origin, o.TLSConfig = "http://sdk-handler.invalid", tlsConfig
	tunnel := startFixtureTunnel(t, context.Background(), o, dial, testHandlerOrigin(handler))
	select {
	case got := <-prefix:
		if got != "prefix" {
			t.Fatalf("prefix: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("flush did not expose prefix while handler was waiting")
	}
	finish()
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPFidelityWriteDeadline(t *testing.T) {
	outcome := make(chan error, 1)
	origin := testHandlerOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			outcome <- err
			return
		}
		_, _ = io.WriteString(w, "prefix")
		outcome <- controller.Flush()
	}))
	origin.start(context.Background())
	defer origin.close()
	connection, err := origin.dial(context.Background(), "tcp", "sdk-handler.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = io.WriteString(connection, "GET / HTTP/1.1\r\nHost: sdk-handler.invalid\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	// The peer deliberately never reads. The existing net.Pipe write is
	// interrupted by ResponseController's deadline, with no listener involved.
	select {
	case err := <-outcome:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("write deadline: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow pipe consumer did not hit bounded write deadline")
	}
}

func TestHTTPFidelityEarlyFailure(t *testing.T) {
	for _, c := range []struct {
		name    string
		handler http.Handler
	}{
		{"body-reader-error", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(202)
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		})},
		{"undeclared-trailer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(202)
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			w.Header().Set(http.TrailerPrefix+"X-Late", "unsupported")
		})},
	} {
		for _, mode := range []string{"buffered", "streaming"} {
			t.Run(c.name+"/"+mode, func(t *testing.T) {
				got := observeResponse(t, mode, "GET", c.handler)
				if mode == "buffered" {
					if got.status != 502 {
						t.Fatalf("failed body became status %d", got.status)
					}
				} else {
					if got.status != 202 || got.body != "prefix" {
						t.Fatalf("final status/body changed: %d %q", got.status, got.body)
					}
					terminal := got.frames[len(got.frames)-1].GetConnectionClose()
					if terminal == nil || terminal.ErrorMessage == "" {
						t.Fatal("failed body became successful EOF")
					}
					for _, frame := range got.frames {
						if frame.GetConnectionHalfClose() != nil {
							t.Fatal("failed body emitted successful terminal frame")
						}
					}
				}
			})
		}
	}
}

func TestHTTPFidelityInformationalLimit(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", "</one>; rel=preload")
		w.Header().Add("Link", "</two>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Link", "</final>; rel=canonical")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "done")
	})
	var codes []int
	var hints textproto.MIMEHeader
	reference, body := directHandlerResponse(t, "GET", handler, &httptrace.ClientTrace{Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
		codes = append(codes, code)
		hints = header
		return nil
	}})
	if !reflect.DeepEqual(codes, []int{103}) || len(hints.Values("Link")) != 2 {
		t.Fatalf("reference did not emit real informational metadata: %v %v", codes, hints)
	}
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			got := observeResponse(t, mode, "GET", handler)
			headers := common.DecodeHTTPResponseHeaders(got.headers, got.fields)
			if got.status != reference.StatusCode || got.body != body || !reflect.DeepEqual(headers.Values("Link"), reference.Header.Values("Link")) {
				t.Fatalf("final response: %d %q %v", got.status, got.body, headers)
			}
			metadata := 0
			for _, frame := range got.frames {
				if frame.GetHttpResponse() != nil || frame.GetConnectionAccept() != nil {
					metadata++
				}
			}
			if metadata != 1 {
				t.Fatalf("unexpected metadata frames: %d", metadata)
			}
			t.Log("direct pipe delivered 1/1 informational response; tunnel delivers 0/1 and preserves final 201 with 4 body bytes (unsupported 1xx forwarding)")
		})
	}
}

func TestHTTPFidelityUnsupportedUpgrade(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "fixture")
		w.WriteHeader(101)
	})
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			got := observeResponse(t, mode, "GET", handler)
			if mode == "buffered" {
				if got.status != 502 || !strings.Contains(got.body, "WebSocket transport") {
					t.Fatalf("unsupported upgrade: %d %q", got.status, got.body)
				}
			} else if !strings.Contains(got.rejection, "WebSocket transport") {
				t.Fatalf("unsupported upgrade: %q", got.rejection)
			}
		})
	}
}
