package host

import (
	"context"
	"errors"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/protobuf/proto"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestHTTPFidelityLegacyCookieAmbiguity(t *testing.T) {
	// This is a valid cookie value containing a comma and an equals sign. The
	// historical split heuristic mistakes part of it for a third cookie.
	dst := make(http.Header)
	copyApplicationResponseHeaders(dst, map[string]string{"Set-Cookie": "first=one,fragment=two; Path=/, second=three; Path=/"})
	if len(dst.Values("Set-Cookie")) != 3 {
		t.Fatalf("legacy fallback changed: %v", dst)
	}
	t.Log("old wire fallback emits 3 cookie fields for 2 original cookies; exact recovery is impossible")
}

func TestHTTPFidelityHostWireVersions(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming"} {
		for _, version := range []string{"new-client/new-host", "old-client/new-host"} {
			t.Run(mode+"/"+version, func(t *testing.T) {
				fields := []*pb.HttpHeader{{Name: "Set-Cookie", Value: "first=one,fragment=two; Path=/"}, {Name: "set-cookie", Value: "second=three; Path=/"}, {Name: "Set-Cookie", Value: "tunn_session=blocked; Path=/"}, {Name: "Set-Cookie", Value: "__Host-tunn_session=blocked; Path=/; Secure"}, {Name: "Set-Cookie", Value: "__Secure-tunn_session=blocked; Path=/; Secure"}, {Name: "X-Repeat", Value: "one,two"}, {Name: "x-repeat", Value: "three"}, {Name: "Tunn-Limit-Reason", Value: "forged"}}
				legacy := map[string]string{"Set-Cookie": "first=one,fragment=two; Path=/, second=three; Path=/, tunn_session=blocked; Path=/, __Host-tunn_session=blocked; Path=/; Secure, __Secure-tunn_session=blocked; Path=/; Secure", "X-Repeat": "one,two, three", "X-Map-Only": "stale", "Tunn-Limit-Reason": "forged"}
				if version == "old-client/new-host" {
					fields = nil
				}
				stream := &meteringFixtureStream{}
				tunnel := &TunnelConnection{Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse)}
				if mode == "streaming" {
					tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true}
				}
				stream.hook = func(message *pb.TunnelMessage) error {
					if request := message.GetHttpRequest(); request != nil {
						response := &pb.HttpResponse{ConnectionId: request.ConnectionId, StatusCode: 202, Headers: legacy, HeaderFields: fields, Body: []byte("abc")}
						wire, err := proto.Marshal(response)
						if err != nil {
							return err
						}
						decoded := &pb.HttpResponse{}
						if err = proto.Unmarshal(wire, decoded); err != nil {
							return err
						}
						tunnel.pendingMu.RLock()
						ch := tunnel.pendingRequests[request.ConnectionId]
						tunnel.pendingMu.RUnlock()
						ch <- decoded
					}
					if open := message.GetConnectionOpen(); open != nil {
						response := &pb.HttpResponseHead{StatusCode: 202, Headers: legacy, HeaderFields: fields}
						wire, err := proto.Marshal(response)
						if err != nil {
							return err
						}
						decoded := &pb.HttpResponseHead{}
						if err = proto.Unmarshal(wire, decoded); err != nil {
							return err
						}
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: decoded}}})
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte("abc")}}})
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId}}})
					}
					return nil
				}
				request := httptest.NewRequest("GET", "http://fixture.invalid/", nil)
				ctx, cancel := context.WithTimeout(request.Context(), time.Second)
				defer cancel()
				request = request.WithContext(ctx)
				writer := httptest.NewRecorder()
				if err := (&ProxyServer{}).proxyHTTPOverGRPC(writer, request, tunnel); err != nil {
					t.Fatal(err)
				}
				if writer.Code != 202 || writer.Body.String() != "abc" || writer.Header().Get("Tunn-Limit-Reason") != "" {
					t.Fatalf("response: %d %q %v", writer.Code, writer.Body.String(), writer.Header())
				}
				if version == "new-client/new-host" {
					if !reflect.DeepEqual(writer.Header().Values("X-Repeat"), []string{"one,two", "three"}) || len(writer.Header().Values("Set-Cookie")) != 2 || writer.Header().Get("X-Map-Only") != "" {
						t.Fatalf("list fidelity/filter/precedence: %v", writer.Header())
					}
				} else if len(writer.Header().Values("X-Repeat")) != 1 || len(writer.Header().Values("Set-Cookie")) != 3 || writer.Header().Get("X-Map-Only") != "stale" {
					t.Fatalf("legacy fidelity changed: %v", writer.Header())
				}
			})
		}
	}
}

func TestHTTPFidelityHostBodylessCompletion(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming"} {
		for _, c := range []struct {
			method string
			status int
		}{{"HEAD", 200}, {"GET", 204}, {"GET", 304}} {
			t.Run(mode+"/"+c.method+"/"+http.StatusText(c.status), func(t *testing.T) {
				stream := &meteringFixtureStream{}
				tunnel := &TunnelConnection{Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse)}
				if mode == "streaming" {
					tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true}
				}
				stream.hook = func(message *pb.TunnelMessage) error {
					if req := message.GetHttpRequest(); req != nil {
						tunnel.pendingMu.RLock()
						ch := tunnel.pendingRequests[req.ConnectionId]
						tunnel.pendingMu.RUnlock()
						ch <- &pb.HttpResponse{StatusCode: int32(c.status), Body: []byte("must not appear")}
					}
					if open := message.GetConnectionOpen(); open != nil {
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: int32(c.status)}}}})
					}
					return nil
				}
				request := httptest.NewRequest(c.method, "http://fixture.invalid/", nil)
				ctx, cancel := context.WithTimeout(request.Context(), time.Second)
				defer cancel()
				writer := httptest.NewRecorder()
				if err := (&ProxyServer{}).proxyHTTPOverGRPC(writer, request.WithContext(ctx), tunnel); err != nil {
					t.Fatalf("bodyless response waited for a terminal frame: %v", err)
				}
				if writer.Code != c.status || writer.Body.Len() != 0 {
					t.Fatalf("bodyless response: %d %q", writer.Code, writer.Body.String())
				}
			})
		}
	}
}

func TestHTTPFidelityHostTrailers(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			stream := &meteringFixtureStream{}
			tunnel := &TunnelConnection{Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse), Capabilities: map[string]bool{common.CapabilityHTTPResponseTrailersV1: true}}
			if mode == "streaming" {
				tunnel.Capabilities[common.CapabilityHTTPStreamV1] = true
			}
			names := []string{"X-End", "Tunn-Limit-Reason", "Set-Cookie"}
			fields := []*pb.HttpHeader{{Name: "X-End", Value: "one,two"}, {Name: "X-End", Value: "three"}, {Name: "Tunn-Limit-Reason", Value: "forged"}, {Name: "Set-Cookie", Value: "tunn_session=blocked; Path=/"}}
			stream.hook = func(message *pb.TunnelMessage) error {
				if req := message.GetHttpRequest(); req != nil {
					tunnel.pendingMu.RLock()
					ch := tunnel.pendingRequests[req.ConnectionId]
					tunnel.pendingMu.RUnlock()
					ch <- &pb.HttpResponse{StatusCode: 202, Body: []byte("prefix"), TrailerNames: names, Trailers: fields}
				}
				if open := message.GetConnectionOpen(); open != nil {
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 202, TrailerNames: names}}}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte("prefix")}}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId, Trailers: fields}}})
				}
				return nil
			}
			writer := httptest.NewRecorder()
			request := httptest.NewRequest("GET", "http://fixture.invalid/", nil)
			if err := (&ProxyServer{}).proxyHTTPOverGRPC(writer, request, tunnel); err != nil {
				t.Fatal(err)
			}
			response := writer.Result()
			defer response.Body.Close()
			if response.StatusCode != 202 || writer.Body.String() != "prefix" || !reflect.DeepEqual(response.Trailer.Values("X-End"), []string{"one,two", "three"}) || response.Header.Get("X-End") != "" || response.Trailer.Get("Tunn-Limit-Reason") != "" || response.Trailer.Get("Set-Cookie") != "" {
				t.Fatalf("response headers=%v trailers=%v body=%q", response.Header, response.Trailer, writer.Body.String())
			}
		})
	}
}

func TestHTTPFidelityTerminalErrors(t *testing.T) {
	for _, c := range []struct {
		name, length string
		close        bool
		message      string
		trailers     []*pb.HttpHeader
		wantError    bool
	}{
		{"complete", "3", false, "", nil, false},
		{"unknown-complete", "", false, "", nil, false},
		{"zero-excess", "0", false, "", nil, true}, // abc cannot satisfy a known zero length.
		{"truncated", "4", false, "", nil, true},
		{"excess", "2", false, "", nil, true},
		{"empty-close", "", true, "", nil, true},
		{"error-close", "", true, "upstream failed", nil, true},
		{"undeclared-trailer", "", false, "", []*pb.HttpHeader{{Name: "X-Late", Value: "no"}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			stream := &meteringFixtureStream{}
			tunnel := &TunnelConnection{Stream: stream, Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityHTTPResponseTrailersV1: true}}
			stream.hook = func(message *pb.TunnelMessage) error {
				if open := message.GetConnectionOpen(); open != nil {
					head := &pb.HttpResponseHead{StatusCode: 202}
					if c.length != "" {
						head.HeaderFields = []*pb.HttpHeader{{Name: "Content-Length", Value: c.length}}
					}
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: head}}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte("abc")}}})
					if c.close {
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{ConnectionClose: &pb.ConnectionClose{ConnectionId: open.ConnectionId, ErrorMessage: c.message}}})
					} else {
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId, Trailers: c.trailers}}})
					}
				}
				return nil
			}
			writer := httptest.NewRecorder()
			err := (&ProxyServer{}).proxyHTTPOverGRPC(writer, httptest.NewRequest("GET", "http://fixture.invalid/", nil), tunnel)
			if c.wantError {
				var truncated *truncatedHTTPResponseError
				if !responseHasStarted(err) || !errors.As(err, &truncated) || writer.Code != 202 {
					t.Fatalf("failed final response became success: %d %v", writer.Code, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPFidelityAbortDownstream(t *testing.T) {
	proxy, tunnel, _, stream := meteringRelay(t, true, "")
	tunnel.AllowedEmails = nil
	stream.hook = func(message *pb.TunnelMessage) error {
		if open := message.GetConnectionOpen(); open != nil {
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 202}}}})
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte("prefix")}}})
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{ConnectionClose: &pb.ConnectionClose{ConnectionId: open.ConnectionId, ErrorMessage: "upstream read failed"}}})
		}
		return nil
	}
	// Reuse the existing private pipe listener; no httptest server constructor
	// (which binds a TCP listener) and no second relay fixture are needed.
	listener := newWebSocketMemoryListener("fixture.invalid:80")
	server := &http.Server{Handler: proxy.createHandler()}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	defer func() { _ = server.Close(); <-done }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return listener.Dial(ctx) }}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("http://api.tunn.test/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if response.StatusCode != 202 || string(body) != "prefix" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("downstream final response: %d %q %v", response.StatusCode, body, err)
	}
}

func TestHTTPFidelityInvalidFinalMetadata(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming"} {
		for _, status := range []int32{0, 101, 103, 600} {
			t.Run(fmt.Sprintf("%s/%d", mode, status), func(t *testing.T) {
				stream := &meteringFixtureStream{}
				tunnel := &TunnelConnection{Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse)}
				if mode == "streaming" {
					tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true}
				}
				stream.hook = func(message *pb.TunnelMessage) error {
					if req := message.GetHttpRequest(); req != nil {
						tunnel.pendingMu.RLock()
						ch := tunnel.pendingRequests[req.ConnectionId]
						tunnel.pendingMu.RUnlock()
						ch <- &pb.HttpResponse{StatusCode: status}
					}
					if open := message.GetConnectionOpen(); open != nil {
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: status}}}})
					}
					return nil
				}
				writer := httptest.NewRecorder()
				err := (&ProxyServer{}).proxyHTTPOverGRPC(writer, httptest.NewRequest("GET", "http://fixture.invalid/", nil), tunnel)
				if err == nil || responseHasStarted(err) || writer.Body.Len() != 0 || writer.Flushed {
					t.Fatalf("invalid final metadata was committed: %d %v", status, err)
				}
			})
		}
	}
}
