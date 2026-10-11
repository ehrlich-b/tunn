package host

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Discard request chunks rather than retaining a 100 MiB upload in the mock.
func uploadResponseProxy(t *testing.T, status int, prefix string) (*ProxyServer, *TunnelConnection, *atomic.Int32) {
	t.Helper()
	var closes atomic.Int32
	tunnel := &TunnelConnection{TunnelID: "api", Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityHTTPResponseTrailersV1: true}}
	tunnel.Stream = &securityStream{onSend: func(message *pb.TunnelMessage) error {
		finish := func(id string) {
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id, Trailers: []*pb.HttpHeader{{Name: "X-End", Value: "complete"}}}}})
		}
		if open := message.GetConnectionOpen(); open != nil {
			head := &pb.HttpResponseHead{StatusCode: int32(status)}
			if common.HTTPResponseHasBody(open.HttpRequest.Method, status) {
				head.TrailerNames = []string{"X-End"}
			}
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: head}}})
			if prefix != "" {
				tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte(prefix)}}})
			} else if len(head.TrailerNames) > 0 {
				finish(open.ConnectionId)
			}
		}
		if end := message.GetConnectionHalfClose(); end != nil && prefix != "" {
			finish(end.ConnectionId)
		}
		if message.GetConnectionClose() != nil {
			closes.Add(1)
		}
		return nil
	}}
	cfg := webproxyTestConfig()
	cfg.Domain = "tunn.test"
	server := NewTunnelServer(cfg, nil, nil, nil)
	server.tunnels["api"] = tunnel
	return &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: server}, tunnel, &closes
}

func assertUploadResponseCleanup(t *testing.T, tunnel *TunnelConnection, closes *atomic.Int32) {
	t.Helper()
	tunnel.pendingMu.RLock()
	pending := len(tunnel.pendingStreams)
	tunnel.pendingMu.RUnlock()
	if pending != 0 || closes.Load() != 1 {
		t.Fatalf("pending streams=%d logical closes=%d", pending, closes.Load())
	}
}

func TestHTTPFidelityUnknownUploadLimitBeforeEmptyResponse(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			proxy, tunnel, closes := uploadResponseProxy(t, status, "")
			upload := &uploadBody{remaining: MaxBodySize + 1}
			returned := make(chan struct{})
			response, body, err := responseFailureMemoryResponse(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(returned)
				r.Method, r.Body, r.ContentLength = http.MethodPost, upload, -1
				proxy.handleWebProxy(w, r)
			}))
			waitResponseSignal(t, returned)
			if err != nil || response == nil || response.StatusCode != http.StatusRequestEntityTooLarge || response.Header.Get("Tunn-Limit-Reason") != "request_body_too_large" || !strings.Contains(body, "104857600 bytes (100 MiB)") {
				t.Fatalf("oversized upload hidden by early %d: response=%v body=%q error=%v", status, response, body, err)
			}
			if upload.read != MaxBodySize+1 || len(response.Trailer) != 0 {
				t.Fatalf("size probe=%d trailers=%v", upload.read, response.Trailer)
			}
			assertUploadResponseCleanup(t, tunnel, closes)
		})
	}
}

type uploadCleanupWriter struct {
	http.ResponseWriter
	cancel context.CancelFunc
}

func (w uploadCleanupWriter) SetReadDeadline(time.Time) error {
	// Model net/http's background reader cancelling the request when cleanup
	// interrupts unfinished HTTP/1 input. Hold cleanup briefly so the response
	// owner can observe cancellation before the upload goroutine returns.
	w.cancel()
	time.Sleep(20 * time.Millisecond)
	return nil
}

func TestHTTPFidelityUploadLimitCleanupCancellation(t *testing.T) {
	proxy, tunnel, closes := uploadResponseProxy(t, http.StatusOK, "")
	upload := &uploadBody{remaining: MaxBodySize + 1}
	r := httptest.NewRequest(http.MethodPost, "http://api.tunn.test/", upload)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	r.ContentLength = -1
	w := httptest.NewRecorder()
	proxy.handleWebProxy(uploadCleanupWriter{ResponseWriter: w, cancel: cancel}, r)
	assertUpload413(t, w)
	if ctx.Err() == nil {
		t.Fatal("cleanup did not exercise request cancellation")
	}
	assertUploadResponseCleanup(t, tunnel, closes)
}

type responseLimitUpload struct {
	uploadBody
	release <-chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (b *responseLimitUpload) Read(p []byte) (int, error) {
	select {
	case <-b.release:
		return b.uploadBody.Read(p)
	case <-b.closed:
		return 0, io.ErrClosedPipe
	}
}
func (b *responseLimitUpload) Close() error { b.once.Do(func() { close(b.closed) }); return nil }

func TestHTTPFidelityUploadLimitAfterPrefixAbortsResponse(t *testing.T) {
	proxy, tunnel, closes := uploadResponseProxy(t, http.StatusAccepted, "abc")
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	upload := &responseLimitUpload{uploadBody: uploadBody{remaining: MaxBodySize + 1}, release: release, closed: make(chan struct{})}
	returned := make(chan struct{})
	client := responseFailureMemoryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(returned)
		r.Method, r.Body, r.ContentLength = http.MethodPost, upload, -1
		proxy.handleWebProxy(w, r)
	}))
	response, err := client.Get("http://api.tunn.test/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	prefix := make([]byte, 3)
	if _, err := io.ReadFull(response.Body, prefix); err != nil {
		t.Fatal(err)
	}
	// Only the downstream consumer can release the remaining request bytes.
	unblock()
	suffix, err := io.ReadAll(response.Body)
	waitResponseSignal(t, returned)
	waitResponseSignal(t, upload.closed)
	if response.StatusCode != http.StatusAccepted || string(prefix) != "abc" || len(suffix) != 0 || !errors.Is(err, io.ErrUnexpectedEOF) || len(response.Trailer.Values("X-End")) != 0 {
		t.Fatalf("oversized post-prefix upload: status=%d prefix=%q suffix=%q trailers=%v error=%v", response.StatusCode, prefix, suffix, response.Trailer, err)
	}
	if upload.read != MaxBodySize+1 {
		t.Fatalf("size probe read %d bytes", upload.read)
	}
	assertUploadResponseCleanup(t, tunnel, closes)
}

// Real HTTP/1 chunked framing over crossed pipes, with keep-alive enabled.
// Without EnableFullDuplex, net/http drains the upload before flushing a prefix.
func TestHTTPFidelityChunkedUploadProgressAfterPrefix(t *testing.T) {
	proxy, tunnel, closes := uploadResponseProxy(t, http.StatusAccepted, "abc")
	listener := newWebSocketMemoryListener("fixture.invalid:80")
	ctx, cancel := context.WithCancel(context.Background())
	returned, served := make(chan struct{}), make(chan struct{})
	server := &http.Server{BaseContext: func(net.Listener) context.Context { return ctx }, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(returned)
		proxy.handleWebProxy(w, r)
	})}
	go func() { defer close(served); _ = server.Serve(listener) }()
	defer func() { cancel(); _ = server.Close(); <-served }()
	clientRead, serverWrite := net.Pipe()
	clientWrite, serverRead := net.Pipe()
	client := &responseFailureSplitConn{reader: clientRead, writer: clientWrite}
	peer := &responseFailureSplitConn{reader: serverRead, writer: serverWrite}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	select {
	case listener.connections <- peer:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := io.WriteString(client, "POST / HTTP/1.1\r\nHost: api.tunn.test\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	prefix := make([]byte, 3)
	if _, err := io.ReadFull(response.Body, prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	suffix, err := io.ReadAll(response.Body)
	waitResponseSignal(t, returned)
	if err != nil || response.StatusCode != http.StatusAccepted || string(prefix) != "abc" || len(suffix) != 0 || response.Trailer.Get("X-End") != "complete" {
		t.Fatalf("chunked duplex response: status=%d prefix=%q suffix=%q trailers=%v error=%v", response.StatusCode, prefix, suffix, response.Trailer, err)
	}
	assertUploadResponseCleanup(t, tunnel, closes)
}
