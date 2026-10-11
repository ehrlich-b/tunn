package host

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Two crossed net.Pipes allow a client to end its upload direction while
// retaining its response direction. No listener socket or kernel TCP is used.
type responseFailureSplitConn struct{ reader, writer net.Conn }

func (c *responseFailureSplitConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *responseFailureSplitConn) Write(b []byte) (int, error) { return c.writer.Write(b) }
func (c *responseFailureSplitConn) Close() error                { c.reader.Close(); return c.writer.Close() }
func (c *responseFailureSplitConn) CloseWrite() error           { return c.writer.Close() }
func (c *responseFailureSplitConn) LocalAddr() net.Addr         { return c.reader.LocalAddr() }
func (c *responseFailureSplitConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
}
func (c *responseFailureSplitConn) SetDeadline(t time.Time) error {
	c.reader.SetDeadline(t)
	return c.writer.SetDeadline(t)
}
func (c *responseFailureSplitConn) SetReadDeadline(t time.Time) error {
	return c.reader.SetReadDeadline(t)
}
func (c *responseFailureSplitConn) SetWriteDeadline(t time.Time) error {
	return c.writer.SetWriteDeadline(t)
}
func responseFailureHalfUpload(t *testing.T, h http.Handler) (int, string, error) {
	t.Helper()
	listener := newWebSocketMemoryListener("fixture.invalid:80")
	ctx, cancel := context.WithCancel(context.Background())
	server := &http.Server{Handler: h, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(listener) }()
	defer func() { cancel(); server.Close(); <-done }()
	clientRead, serverWrite := net.Pipe()
	clientWrite, serverRead := net.Pipe()
	client := &responseFailureSplitConn{reader: clientRead, writer: clientWrite}
	peer := &responseFailureSplitConn{reader: serverRead, writer: serverWrite}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	select {
	case listener.connections <- peer:
	case <-time.After(time.Second):
		t.Fatal("pipe accept timed out")
	}
	if _, e := io.WriteString(client, "POST / HTTP/1.1\r\nHost: api.tunn.test\r\nContent-Length: 2\r\nConnection: close\r\n\r\na"); e != nil {
		t.Fatal(e)
	}
	response, e := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "POST"})
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	prefix := make([]byte, 3)
	if _, e = io.ReadFull(response.Body, prefix); e != nil {
		t.Fatal(e)
	}
	if e = client.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	suffix, e := io.ReadAll(response.Body)
	return response.StatusCode, string(prefix) + string(suffix), e
}
func TestHTTPFidelityWireUploadEOFAbortsResponse(t *testing.T) {
	status, body, want := responseFailureHalfUpload(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e := http.NewResponseController(w).EnableFullDuplex(); e != nil {
			panic(e)
		}
		w.WriteHeader(202)
		io.WriteString(w, "abc")
		w.(http.Flusher).Flush()
		if _, e := io.ReadAll(r.Body); e != nil {
			panic(http.ErrAbortHandler)
		}
	}))
	if status != 202 || body != "abc" || !errors.Is(want, io.ErrUnexpectedEOF) {
		t.Fatalf("direct reference=%d %q %v", status, body, want)
	}
	stream := &meteringFixtureStream{}
	tunnel := &TunnelConnection{TunnelID: "api", Stream: stream, Capabilities: map[string]bool{"http-stream-v1": true}, pendingRequests: map[string]chan *pb.HttpResponse{}}
	cfg := webproxyTestConfig()
	cfg.Domain = "tunn.test"
	server := NewTunnelServer(cfg, nil, nil, nil)
	server.tunnels["api"] = tunnel
	p := &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: server}
	stream.hook = func(m *pb.TunnelMessage) error {
		if o := m.GetConnectionOpen(); o != nil {
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: o.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 202}}}})
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: o.ConnectionId, Data: []byte("abc")}}})
		}
		return nil
	}
	status, body, actual := responseFailureHalfUpload(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.handleWebProxy(w, r) }))
	t.Logf("actual HTTP/1 upload: sent 1/2 bytes then half-closed; direct=%v relay status=%d body=%q error=%v", want, status, body, actual)
	if status != 202 || body != "abc" || !errors.Is(actual, io.ErrUnexpectedEOF) {
		t.Fatalf("premature upload EOF was presented as a complete response: %d %q %v", status, body, actual)
	}
}
