package host

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type scheduledUpload struct {
	*io.PipeReader
	closed chan struct{}
	once   sync.Once
}

func (b *scheduledUpload) Close() error {
	err := b.PipeReader.Close()
	b.once.Do(func() { close(b.closed) })
	return err
}

func waitResponseSignal[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("response fixture barrier timed out")
		var zero T
		return zero
	}
}

// Four bounded ownership schedules; the consumer itself acknowledges each
// flushed prefix. No scheduling sleeps, real listener or performance probe.
func TestHTTPFidelityUploadTerminalSchedules(t *testing.T) {
	for _, schedule := range []string{"upload-before-head", "upload-after-prefix", "upload-after-terminal", "error-close-after-upload"} {
		t.Run(schedule, func(t *testing.T) {
			reader, writer := io.Pipe()
			defer writer.Close()
			upload := &scheduledUpload{PipeReader: reader, closed: make(chan struct{})}
			opened := make(chan string, 1)
			halfClosed := make(chan string, 1)
			returned := make(chan struct{})
			var closes atomic.Int32
			stream := &meteringFixtureStream{}
			tunnel := &TunnelConnection{TunnelID: "api", Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse), Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityHTTPResponseTrailersV1: true}}
			cfg := webproxyTestConfig()
			cfg.Domain = "tunn.test"
			server := NewTunnelServer(cfg, nil, nil, nil)
			server.tunnels["api"] = tunnel
			proxy := &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: server}
			stream.hook = func(message *pb.TunnelMessage) error {
				if open := message.GetConnectionOpen(); open != nil {
					opened <- open.ConnectionId
				}
				if end := message.GetConnectionHalfClose(); end != nil {
					halfClosed <- end.ConnectionId
				}
				if message.GetConnectionClose() != nil {
					closes.Add(1)
				}
				return nil
			}
			client := responseFailureMemoryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(returned)
				r.Body = upload
				r.ContentLength = -1
				proxy.proxyToLocal(w, r, "api")
			}))
			type result struct {
				response *http.Response
				err      error
			}
			responseReady := make(chan result, 1)
			go func() { response, err := client.Get("http://api.tunn.test/"); responseReady <- result{response, err} }()
			id := waitResponseSignal(t, opened)
			finishUpload := func() {
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				if got := waitResponseSignal(t, halfClosed); got != id {
					t.Fatalf("upload half-close belongs to %s, want %s", got, id)
				}
			}
			if schedule == "upload-before-head" {
				finishUpload()
			}
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 202, HeaderFields: []*pb.HttpHeader{{Name: "Set-Cookie", Value: "first=one; Path=/"}, {Name: "Set-Cookie", Value: "second=two; Path=/"}}, TrailerNames: []string{"X-End"}}}}})
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte("abc")}}})
			ready := waitResponseSignal(t, responseReady)
			if ready.err != nil {
				t.Fatal(ready.err)
			}
			response := ready.response
			defer response.Body.Close()
			prefix := make([]byte, 3)
			if _, err := io.ReadFull(response.Body, prefix); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 202 || string(prefix) != "abc" || len(response.Cookies()) != 2 || len(response.Trailer.Values("X-End")) != 0 {
				t.Fatalf("prefix metadata/body/trailer=%v %q %v", response.Header, prefix, response.Trailer)
			}
			if schedule == "upload-after-prefix" || schedule == "error-close-after-upload" {
				finishUpload()
			}
			if schedule == "error-close-after-upload" {
				tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{ConnectionClose: &pb.ConnectionClose{ConnectionId: id, ErrorMessage: "publisher body failed"}}})
			} else {
				tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id, Trailers: []*pb.HttpHeader{{Name: "X-End", Value: "one,two"}, {Name: "X-End", Value: "three"}}}}})
			}
			suffix, readErr := io.ReadAll(response.Body)
			if len(suffix) != 0 {
				t.Fatalf("unexpected suffix=%q", suffix)
			}
			if schedule == "error-close-after-upload" {
				if !errors.Is(readErr, io.ErrUnexpectedEOF) || len(response.Trailer.Values("X-End")) != 0 {
					t.Fatalf("failed terminal looked complete: %v %v", readErr, response.Trailer)
				}
			} else if readErr != nil || !reflect.DeepEqual(response.Trailer.Values("X-End"), []string{"one,two", "three"}) {
				t.Fatalf("successful terminal: %v %v", readErr, response.Trailer)
			}
			waitResponseSignal(t, returned)
			waitResponseSignal(t, upload.closed)
			if closes.Load() != 1 {
				t.Fatalf("logical close count=%d", closes.Load())
			}
			tunnel.pendingMu.RLock()
			pending := len(tunnel.pendingStreams)
			tunnel.pendingMu.RUnlock()
			if pending != 0 {
				t.Fatalf("pending streams=%d", pending)
			}
			if schedule == "upload-after-terminal" {
				// Response completion owns cleanup of a still-open request input;
				// it need not await or fabricate a successful upload half-close.
				if _, err := writer.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("completed response retained upload: %v", err)
				}
			}
		})
	}
}

// An upload error and lifetime cancellation are distinct post-metadata exits.
// Both must interrupt a completed prefix, with no terminal application trailer.
func TestHTTPFidelityCancellationAfterPrefix(t *testing.T) {
	for _, phase := range []string{"headers", "body", "before-trailers"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &meteringFixtureStream{}
			tunnel := &TunnelConnection{TunnelID: "api", Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse), Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityHTTPResponseTrailersV1: true}}
			cfg := webproxyTestConfig()
			cfg.Domain = "tunn.test"
			server := NewTunnelServer(cfg, nil, nil, nil)
			server.tunnels["api"] = tunnel
			proxy := &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: server}
			var id string
			var closes atomic.Int32
			stream.hook = func(message *pb.TunnelMessage) error {
				if open := message.GetConnectionOpen(); open != nil {
					id = open.ConnectionId
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 202, HeaderFields: []*pb.HttpHeader{{Name: "Content-Length", Value: "3"}, {Name: "Set-Cookie", Value: "first=one; Path=/"}, {Name: "Set-Cookie", Value: "second=two; Path=/"}}, TrailerNames: []string{"X-End"}}}}})
					if phase != "headers" {
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte(map[string]string{"body": "a", "before-trailers": "abc"}[phase])}}})
					}
				}
				if message.GetConnectionClose() != nil {
					closes.Add(1)
				}
				return nil
			}
			returned := make(chan struct{})
			client := responseFailureMemoryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(returned)
				// Keep the consumer connection alive while canceling only the
				// relay request context, so net/http cannot mask a missing abort.
				r = r.WithContext(ctx)
				proxy.proxyToLocal(w, r, "api")
			}))
			response, err := client.Get("http://api.tunn.test/")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			prefix := ""
			if phase != "headers" {
				size := 3
				if phase == "body" {
					size = 1
				}
				buffer := make([]byte, size)
				if _, err = io.ReadFull(response.Body, buffer); err != nil {
					t.Fatal(err)
				}
				prefix = string(buffer)
			}
			cancel()
			suffix, readErr := io.ReadAll(response.Body)
			waitResponseSignal(t, returned)
			if response.StatusCode != 202 || len(response.Cookies()) != 2 || string(suffix) != "" || !errors.Is(readErr, io.ErrUnexpectedEOF) || len(response.Trailer.Values("X-End")) != 0 || closes.Load() != 1 {
				t.Fatalf("canceled response status=%d prefix=%q suffix=%q error=%v trailers=%v closes=%d", response.StatusCode, prefix, suffix, readErr, response.Trailer, closes.Load())
			}
			// A late terminal after cleanup must not resurrect this request.
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id, Trailers: []*pb.HttpHeader{{Name: "X-End", Value: "too late"}}}}})
			tunnel.pendingMu.RLock()
			pending := len(tunnel.pendingStreams)
			tunnel.pendingMu.RUnlock()
			if pending != 0 {
				t.Fatal("canceled request remained pending")
			}
		})
	}
}
