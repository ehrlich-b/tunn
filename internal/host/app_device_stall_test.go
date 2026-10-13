package host

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type appDeviceObservedConn struct {
	net.Conn
	observe atomic.Bool
	once    sync.Once
	blocked chan struct{}
}

func (c *appDeviceObservedConn) Write(p []byte) (int, error) {
	if c.observe.Load() {
		c.once.Do(func() { close(c.blocked) })
	}
	return c.Conn.Write(p)
}

// An unbuffered pipe blocks on one small frame; this is a stalled-reader test,
// not a large-response or resource-exhaustion input.
func TestAppDeviceStalledWebSocketReaderClosesWithinFiveSeconds(t *testing.T) {
	f := newAppDeviceFixture(t)
	d, token := f.enroll(t, nil)
	f.tunnel.Capabilities = map[string]bool{common.CapabilityWebSocketV1: true}
	opened := make(chan string, 1)
	f.stream.hook = func(m *pb.TunnelMessage) error {
		if open := m.GetConnectionOpen(); open != nil {
			opened <- open.ConnectionId
			f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 101, Headers: map[string]string{"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}}}}})
		}
		return nil
	}
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	observed := &appDeviceObservedConn{Conn: server, blocked: make(chan struct{})}
	r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/socket", nil)
	r.Header.Set("Tunn-Authorization", "Bearer "+token)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	done := make(chan time.Time, 1)
	go func() {
		f.p.createHandler().ServeHTTP(&pipeUpgradeWriter{httptest.NewRecorder(), observed}, r)
		done <- time.Now()
	}()
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, r)
	if err != nil || response.StatusCode != 101 {
		t.Fatal("WS opening failed", err)
	}
	observed.observe.Store(true)
	id := <-opened
	f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: fixtureFrame(1, true, false, []byte("small fixture frame"))}}})
	select {
	case <-observed.blocked:
	case <-time.After(time.Second):
		t.Fatal("writer did not block")
	}
	if _, err = f.p.appDevices.revoke(context.Background(), d.Host, d.Account, d.ID, true); err != nil {
		t.Fatal(err)
	}
	committed := time.Now()
	select {
	case closed := <-done:
		if closed.Sub(committed) > 5*time.Second {
			t.Fatal("stalled WS exceeded cutoff")
		}
		t.Logf("stalled WS cutoff_ms=%d", closed.Sub(committed).Milliseconds())
	case <-time.After(5 * time.Second):
		t.Fatal("stalled WS write survived revoke")
	}
}

type appDevicePipeResponse struct {
	conn    *appDeviceObservedConn
	headers http.Header
}

func (w *appDevicePipeResponse) Header() http.Header               { return w.headers }
func (w *appDevicePipeResponse) WriteHeader(int)                   {}
func (w *appDevicePipeResponse) Write(p []byte) (int, error)       { return w.conn.Write(p) }
func (w *appDevicePipeResponse) Flush()                            {}
func (w *appDevicePipeResponse) SetReadDeadline(t time.Time) error { return w.conn.SetReadDeadline(t) }
func (w *appDevicePipeResponse) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

func TestAppDeviceStalledSSEReaderClosesWithinFiveSeconds(t *testing.T) {
	f := newAppDeviceFixture(t)
	d, token := f.enroll(t, nil)
	appDeviceIdleOrigin(t, f, token)
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	observed := &appDeviceObservedConn{Conn: server, blocked: make(chan struct{})}
	writer := &appDevicePipeResponse{observed, make(http.Header)}
	r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/events", nil)
	r.Header.Set("Tunn-Authorization", "Bearer "+token)
	done := make(chan time.Time, 1)
	go func() {
		defer func() { recover(); server.Close(); done <- time.Now() }()
		f.p.createHandler().ServeHTTP(writer, r)
	}()
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	ready := make([]byte, len(": ready\n\n"))
	if _, err := io.ReadFull(client, ready); err != nil {
		t.Fatal(err)
	}
	observed.observe.Store(true)
	f.tunnel.pendingMu.RLock()
	var id string
	for candidate := range f.tunnel.pendingStreams {
		id = candidate
		break
	}
	f.tunnel.pendingMu.RUnlock()
	if id == "" {
		t.Fatal("no pending SSE")
	}
	f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte("data: stalled\n\n")}}})
	select {
	case <-observed.blocked:
	case <-time.After(time.Second):
		t.Fatal("SSE writer did not block")
	}
	if _, err := f.p.appDevices.revoke(context.Background(), d.Host, d.Account, d.ID, true); err != nil {
		t.Fatal(err)
	}
	committed := time.Now()
	select {
	case closed := <-done:
		if closed.Sub(committed) > 5*time.Second {
			t.Fatal("stalled SSE exceeded cutoff")
		}
		t.Logf("stalled SSE cutoff_ms=%d", closed.Sub(committed).Milliseconds())
	case <-time.After(5 * time.Second):
		t.Fatal("stalled SSE write survived revoke")
	}
}

func TestAppDeviceStalledPublisherCleanupCannotHoldSSEOpen(t *testing.T) {
	f := newAppDeviceFixture(t)
	d, token := f.enroll(t, nil)
	appDeviceIdleOrigin(t, f, token)
	blocked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	original := f.stream.hook
	f.stream.hook = func(m *pb.TunnelMessage) error {
		if m.GetConnectionClose() != nil {
			once.Do(func() { close(blocked) })
			<-release
		}
		return original(m)
	}
	server := appDeviceTLSServer(t, f.p.createHandler())
	t.Cleanup(func() { close(release) })
	stream := appDeviceSSE(t, server, token)
	if _, err := f.p.appDevices.revoke(context.Background(), d.Host, d.Account, d.ID, true); err != nil {
		t.Fatal(err)
	}
	committed := time.Now()
	select {
	case <-blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher cleanup did not stall")
	}
	select {
	case closed := <-stream.closed:
		if closed.Sub(committed) > 5*time.Second {
			t.Fatal("publisher cleanup exceeded cutoff")
		}
		t.Logf("stalled publisher cutoff_ms=%d", closed.Sub(committed).Milliseconds())
	case <-time.After(5 * time.Second):
		t.Fatal("publisher cleanup held SSE open")
	}
}

func TestAppDeviceAdmissionDeadlineDoesNotExpireHealthyStream(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, token := f.enroll(t, nil)
	appDeviceIdleOrigin(t, f, token)
	stream := appDeviceSSE(t, appDeviceTLSServer(t, f.p.createHandler()), token)
	select {
	case <-stream.closed:
		t.Fatal("admission timeout became stream lifetime")
	case <-time.After(2200 * time.Millisecond):
	}
	stream.close()
}

func TestAppDeviceCancellableSendBoundsOneStalledPublisher(t *testing.T) {
	f := newAppDeviceFixture(t)
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var calls atomic.Int64
	f.stream.hook = func(*pb.TunnelMessage) error {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil
	}
	ctx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	first := make(chan error, 1)
	go func() { first <- f.tunnel.SendMessageContext(ctx, &pb.TunnelMessage{}) }()
	<-started
	for n := 0; n < 3; n++ {
		c, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		err := f.tunnel.SendMessageContext(c, &pb.TunnelMessage{})
		cancel()
		if err == nil {
			t.Fatal("stalled send did not honor deadline")
		}
	}
	if err := <-first; err == nil || calls.Load() != 1 {
		t.Fatal("cancellation spawned more publisher senders")
	}
}
