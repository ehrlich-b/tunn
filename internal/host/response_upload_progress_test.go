package host

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/testnet"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"golang.org/x/net/http2"
)

// The HTTP server and client use crossed pipes, including separate upload and
// response directions. A deadline bounds a deliberately unfinished upload.
func responseProgressHTTP1(t *testing.T, h http.Handler) (net.Conn, <-chan struct{}) {
	t.Helper()
	listener := newWebSocketMemoryListener("fixture.invalid:80")
	returned, served := make(chan struct{}, 2), make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { returned <- struct{}{} }()
		h.ServeHTTP(w, r)
	})}
	go func() { defer close(served); _ = server.Serve(listener) }()
	clientRead, serverWrite := net.Pipe()
	clientWrite, serverRead := net.Pipe()
	client := &responseFailureSplitConn{reader: clientRead, writer: clientWrite}
	listener.connections <- &responseFailureSplitConn{reader: serverRead, writer: serverWrite}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close(); <-served })
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "POST / HTTP/1.1\r\nHost: api.tunn.test\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n"); err != nil {
		t.Fatal(err)
	}
	return client, returned
}

func responseProgressProxy(status int, prefix string, terminal bool) (*ProxyServer, *TunnelConnection, *atomic.Int32) {
	var closes atomic.Int32
	tunnel := &TunnelConnection{TunnelID: "api", Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true}}
	tunnel.Stream = &securityStream{onSend: func(message *pb.TunnelMessage) error {
		if open := message.GetConnectionOpen(); open != nil {
			head := &pb.HttpResponseHead{StatusCode: int32(status)}
			if prefix != "" {
				// Upstream reuse policy cannot override unfinished-upload cleanup.
				head.HeaderFields = []*pb.HttpHeader{{Name: "Connection", Value: "keep-alive"}}
			}
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: head}}})
			if prefix != "" {
				tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte(prefix)}}})
			}
			if terminal {
				tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId}}})
			}
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

type responseProgressObservedBody struct {
	io.ReadCloser
	readStopped atomic.Bool
	closes      atomic.Int32
}

func (b *responseProgressObservedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.readStopped.Store(true)
	}
	return n, err
}

func (b *responseProgressObservedBody) Close() error {
	b.closes.Add(1)
	return b.ReadCloser.Close()
}

// The direct handler is an independent wire oracle: response completion does
// not require the caller to finish a one-byte chunked upload first.
func TestHTTPFidelityCompletedResponseWithOpenWireUpload(t *testing.T) {
	for _, mode := range []string{"direct", "relay"} {
		t.Run(mode, func(t *testing.T) {
			var handler http.Handler
			var tunnel *TunnelConnection
			var closes *atomic.Int32
			var upload *responseProgressObservedBody
			if mode == "direct" {
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_ = http.NewResponseController(w).EnableFullDuplex()
					w.WriteHeader(http.StatusAccepted)
					_, _ = io.WriteString(w, "abc")
					w.(http.Flusher).Flush()
				})
			} else {
				var proxy *ProxyServer
				proxy, tunnel, closes = responseProgressProxy(http.StatusAccepted, "abc", true)
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upload = &responseProgressObservedBody{ReadCloser: r.Body}
					r.Body = upload
					proxy.handleWebProxy(w, r)
				})
			}
			client, returned := responseProgressHTTP1(t, handler)
			reader := bufio.NewReader(client)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			// Keep the upload open until the successful response EOF is observed.
			if response.StatusCode != http.StatusAccepted || string(body) != "abc" || err != nil {
				t.Errorf("completed response with open upload: status=%d body=%q error=%v", response.StatusCode, body, err)
			}
			if err != nil {
				_ = client.Close() // release the baseline's blocked cleanup
			}
			waitResponseSignal(t, returned)
			if tunnel != nil {
				assertUploadResponseCleanup(t, tunnel, closes)
				if !upload.readStopped.Load() || upload.closes.Load() != 1 {
					t.Errorf("upload reader stopped=%v body closes=%d", upload.readStopped.Load(), upload.closes.Load())
				}
				if err == nil {
					if _, nextErr := reader.Peek(1); !response.Close || nextErr != io.EOF {
						t.Errorf("unfinished upload connection retained: close=%v next read=%v", response.Close, nextErr)
					}
				}
			}
		})
	}
}

// An upload consumed before the response must leave the connection reusable;
// cleanup must not set an expired read deadline or affect the next request.
func TestHTTPFidelityCompletedUploadKeepsConnection(t *testing.T) {
	proxy, tunnel, closes := uploadResponseProxy(t, http.StatusAccepted, "abc")
	stream := tunnel.Stream.(*securityStream)
	respond := stream.onSend
	var opened *pb.TunnelMessage
	stream.onSend = func(message *pb.TunnelMessage) error {
		if message.GetConnectionOpen() != nil {
			opened = message
			return nil
		}
		if message.GetConnectionHalfClose() != nil {
			if err := respond(opened); err != nil {
				return err
			}
		}
		return respond(message)
	}
	client, returned := responseProgressHTTP1(t, http.HandlerFunc(proxy.handleWebProxy))
	reader := bufio.NewReader(client)
	for index := 0; index < 2; index++ {
		if index == 0 {
			if _, err := io.WriteString(client, "0\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: api.tunn.test\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
		}
		response, err := http.ReadResponse(reader, &http.Request{Method: []string{http.MethodPost, http.MethodGet}[index]})
		if err != nil {
			t.Fatal(err)
		}
		prefix := make([]byte, 3)
		if _, err := io.ReadFull(response.Body, prefix); err != nil {
			t.Fatal(err)
		}
		if index == 0 && response.Close {
			t.Fatal("consumed upload disabled keep-alive")
		}
		suffix, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusAccepted || string(prefix) != "abc" || len(suffix) != 0 || response.Trailer.Get("X-End") != "complete" {
			t.Fatalf("request %d: response=%v prefix=%q suffix=%q error=%v", index, response, prefix, suffix, err)
		}
		waitResponseSignal(t, returned)
	}
	tunnel.pendingMu.RLock()
	pending := len(tunnel.pendingStreams)
	tunnel.pendingMu.RUnlock()
	if pending != 0 || closes.Load() != 2 {
		t.Fatalf("two-request cleanup: pending=%d closes=%d", pending, closes.Load())
	}
}

// A completed application refusal and a flushed, ongoing 202 must both reach
// the caller before upload EOF. The caller may need that head to make progress.
func TestHTTPFidelityHeadersBeforeUploadEOF(t *testing.T) {
	for _, protocol := range []string{"HTTP1", "HTTP2"} {
		for _, status := range []int{http.StatusAccepted, http.StatusForbidden} {
			for _, mode := range []string{"direct", "relay"} {
				t.Run(protocol+"/"+http.StatusText(status)+"/"+mode, func(t *testing.T) {
					var handler http.Handler
					var tunnel *TunnelConnection
					var closes *atomic.Int32
					if mode == "direct" {
						handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							_ = http.NewResponseController(w).EnableFullDuplex()
							w.WriteHeader(status)
							w.(http.Flusher).Flush()
							if status == http.StatusAccepted {
								_, _ = io.Copy(io.Discard, r.Body)
							}
						})
					} else {
						var proxy *ProxyServer
						proxy, tunnel, closes = responseProgressProxy(status, "", status == http.StatusForbidden)
						handler = http.HandlerFunc(proxy.handleWebProxy)
					}
					var response *http.Response
					var err error
					if protocol == "HTTP1" {
						client, returned := responseProgressHTTP1(t, handler)
						response, err = http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
						_ = client.Close()
						waitResponseSignal(t, returned)
					} else {
						response, err = responseProgressHTTP2(t, handler)
					}
					if err != nil || response == nil || response.StatusCode != status {
						t.Errorf("head withheld before upload EOF: response=%v error=%v", response, err)
					}
					if tunnel != nil {
						assertUploadResponseCleanup(t, tunnel, closes)
					}
				})
			}
		}
	}
}

func responseProgressHTTP2(t *testing.T, handler http.Handler) (*http.Response, error) {
	t.Helper()
	local, remote := testnet.Pair()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	served, returned := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(served)
		(&http2.Server{}).ServeConn(remote, &http2.ServeConnOpts{Context: ctx, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(returned)
			handler.ServeHTTP(w, r)
		})})
	}()
	transport := &http2.Transport{AllowHTTP: true}
	client, err := transport.NewClientConn(local)
	if err != nil {
		_ = local.Close()
		_ = remote.Close()
		<-served
		t.Fatal(err)
	}
	defer func() { _ = client.Close(); _ = remote.Close(); <-served }()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://api.tunn.test/", reader)
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan struct{})
	go func() { defer close(written); _, _ = io.WriteString(writer, "a") }()
	response, err := client.RoundTrip(request)
	cancel()
	_ = reader.Close()
	_ = writer.Close()
	<-written
	if response != nil {
		_ = response.Body.Close()
	}
	waitResponseSignal(t, returned)
	return response, err
}
