package host

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// No client error injection: the relay's request reader fails only after it has
// flushed a response prefix. Its publisher deliberately never emits a response
// half-close. An independent direct handler abort is the expected result.
type responseFailureUploadBody struct {
	release <-chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (b *responseFailureUploadBody) Read([]byte) (int, error) {
	select {
	case <-b.release:
		return 0, io.ErrUnexpectedEOF
	case <-b.closed:
		return 0, io.ErrClosedPipe
	}
}
func (b *responseFailureUploadBody) Close() error { b.once.Do(func() { close(b.closed) }); return nil }

type responseFailureReleaseWriter struct {
	http.ResponseWriter
	release func()
	written bool
}

func (w *responseFailureReleaseWriter) Write(b []byte) (int, error) {
	n, e := w.ResponseWriter.Write(b)
	if n > 0 {
		w.written = true
	}
	return n, e
}
func (w *responseFailureReleaseWriter) Flush() {
	w.ResponseWriter.(http.Flusher).Flush()
	if w.written {
		w.release()
	}
}
func (w *responseFailureReleaseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func responseFailureMemoryClient(t *testing.T, h http.Handler) *http.Client {
	t.Helper()
	listener := newWebSocketMemoryListener("fixture.invalid:80")
	server := &http.Server{Handler: h}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return listener.Dial(ctx) }}
	t.Cleanup(func() { transport.CloseIdleConnections(); server.Close(); <-done })
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}
func responseFailureMemoryResponse(t *testing.T, h http.Handler) (*http.Response, string, error) {
	t.Helper()
	res, e := responseFailureMemoryClient(t, h).Get("http://api.tunn.test/")
	if e != nil {
		return nil, "", e
	}
	defer res.Body.Close()
	body, e := io.ReadAll(res.Body)
	return res, string(body), e
}
func responseFailureReadMemory(t *testing.T, h http.Handler) (int, string, error) {
	t.Helper()
	res, body, e := responseFailureMemoryResponse(t, h)
	if res == nil {
		return 0, body, e
	}
	return res.StatusCode, body, e
}

// Direct recorder callers have no net/http panic recovery. They must receive
// forwarding errors, including the original cause and truncation marker, after
// the request and its pending stream have been cleaned up.
func TestProxyToLocalReturnsResponseErrors(t *testing.T) {
	for _, phase := range []string{"before-head", "after-prefix", "complete"} {
		t.Run(phase, func(t *testing.T) {
			stream := &meteringFixtureStream{}
			tunnel := &TunnelConnection{TunnelID: "api", Stream: stream, Capabilities: map[string]bool{"http-stream-v1": true}, pendingRequests: map[string]chan *pb.HttpResponse{}}
			cfg := webproxyTestConfig()
			cfg.Domain = "tunn.test"
			server := NewTunnelServer(cfg, nil, nil, nil)
			server.tunnels["api"] = tunnel
			proxy := &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: server}
			closes := 0
			stream.hook = func(message *pb.TunnelMessage) error {
				if open := message.GetConnectionOpen(); open != nil {
					accept := &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: phase != "before-head", ErrorMessage: "publisher rejected request", HttpResponse: &pb.HttpResponseHead{StatusCode: 202}}
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: accept}})
					if accept.Success {
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte("abc")}}})
						if phase == "complete" {
							tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId}}})
						}
					}
				}
				if message.GetConnectionClose() != nil {
					closes++
				}
				return nil
			}
			request := httptest.NewRequest(http.MethodGet, "http://api.tunn.test/", nil)
			recorder := httptest.NewRecorder()
			var writer http.ResponseWriter = recorder
			var upload *responseFailureUploadBody
			if phase == "after-prefix" {
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				upload = &responseFailureUploadBody{release: release, closed: make(chan struct{})}
				request.Body, request.ContentLength = upload, -1
				writer = &responseFailureReleaseWriter{ResponseWriter: recorder, release: unblock}
			}
			err := proxy.proxyToLocal(writer, request, "api")
			var truncated *truncatedHTTPResponseError
			switch phase {
			case "before-head":
				if err == nil || responseHasStarted(err) || errors.As(err, &truncated) || recorder.Code != http.StatusBadGateway {
					t.Fatalf("pre-header failure: error=%v status=%d body=%q", err, recorder.Code, recorder.Body.String())
				}
			case "after-prefix":
				if !errors.Is(err, io.ErrUnexpectedEOF) || !responseHasStarted(err) || !errors.As(err, &truncated) || recorder.Code != 202 || recorder.Body.String() != "abc" {
					t.Fatalf("truncated response: error=%v status=%d body=%q", err, recorder.Code, recorder.Body.String())
				}
				select {
				case <-upload.closed:
				default:
					t.Fatal("returned without closing the request body")
				}
			case "complete":
				if err != nil || recorder.Code != 202 || recorder.Body.String() != "abc" {
					t.Fatalf("complete response: error=%v status=%d body=%q", err, recorder.Code, recorder.Body.String())
				}
			}
			tunnel.pendingMu.RLock()
			pending := len(tunnel.pendingStreams)
			tunnel.pendingMu.RUnlock()
			if pending != 0 || closes != 1 {
				t.Fatalf("cleanup: pending=%d logical closes=%d", pending, closes)
			}
		})
	}
}

func TestHTTPFidelityUploadFailureAbortsResponse(t *testing.T) {
	wantStatus, wantBody, wantErr := responseFailureReadMemory(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		io.WriteString(w, "abc")
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	if wantStatus != 202 || wantBody != "abc" || !errors.Is(wantErr, io.ErrUnexpectedEOF) {
		t.Fatalf("independent abort reference=%d %q %v", wantStatus, wantBody, wantErr)
	}
	stream := &meteringFixtureStream{}
	tunnel := &TunnelConnection{TunnelID: "api", Stream: stream, Capabilities: map[string]bool{"http-stream-v1": true}, pendingRequests: map[string]chan *pb.HttpResponse{}}
	cfg := webproxyTestConfig()
	cfg.Domain = "tunn.test"
	server := NewTunnelServer(cfg, nil, nil, nil)
	server.tunnels["api"] = tunnel
	proxy := &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: server}
	stream.hook = func(m *pb.TunnelMessage) error {
		if o := m.GetConnectionOpen(); o != nil {
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: o.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 202}}}})
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: o.ConnectionId, Data: []byte("abc")}}})
		}
		return nil
	}
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	upload := &responseFailureUploadBody{release: release, closed: make(chan struct{})}
	gotStatus, gotBody, gotErr := responseFailureReadMemory(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = upload
		r.ContentLength = -1
		proxy.handleWebProxy(&responseFailureReleaseWriter{ResponseWriter: w, release: unblock}, r)
	}))
	select {
	case <-upload.closed:
	case <-time.After(time.Second):
		t.Fatal("upload reader was not closed")
	}
	tunnel.pendingMu.RLock()
	pending := len(tunnel.pendingStreams)
	tunnel.pendingMu.RUnlock()
	if pending != 0 {
		t.Fatal("pending request leak")
	}
	t.Logf("independent reference=%d %q err=%v; relay=%d %q err=%v; pending=%d", wantStatus, wantBody, wantErr, gotStatus, gotBody, gotErr, pending)
	if gotStatus != wantStatus || gotBody != wantBody || !errors.Is(gotErr, io.ErrUnexpectedEOF) {
		t.Fatalf("request-upload failure became successful downstream EOF: status=%d body=%q error=%v; expected partial-body error %v", gotStatus, gotBody, gotErr, wantErr)
	}
}
