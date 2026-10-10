package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

// This fixture constructs and parses frames independently of the forwarding
// code, so a shared framing bug cannot make an echo test pass.
func fixtureFrame(opcode byte, fin, masked bool, payload []byte) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	header := []byte{first, 0}
	switch {
	case len(payload) < 126:
		header[1] = byte(len(payload))
	case len(payload) <= 65535:
		header[1] = 126
		header = binary.BigEndian.AppendUint16(header, uint16(len(payload)))
	default:
		header[1] = 127
		header = binary.BigEndian.AppendUint64(header, uint64(len(payload)))
	}
	if masked {
		header[1] |= 0x80
		mask := []byte{0x12, 0x34, 0x56, 0x78}
		header = append(header, mask...)
		for i, b := range payload {
			header = append(header, b^mask[i%4])
		}
	} else {
		header = append(header, payload...)
	}
	return header
}

type fixtureWireFrame struct {
	opcode  byte
	fin     bool
	payload []byte
}

func fixtureReadFrame(r io.Reader, wantMasked bool) (fixtureWireFrame, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return fixtureWireFrame{}, err
	}
	if (h[1]&0x80 != 0) != wantMasked {
		return fixtureWireFrame{}, fmt.Errorf("unexpected frame mask %x", h)
	}
	n := uint64(h[1] & 0x7f)
	if n == 126 {
		var p [2]byte
		if _, err := io.ReadFull(r, p[:]); err != nil {
			return fixtureWireFrame{}, err
		}
		n = uint64(binary.BigEndian.Uint16(p[:]))
	} else if n == 127 {
		var p [8]byte
		if _, err := io.ReadFull(r, p[:]); err != nil {
			return fixtureWireFrame{}, err
		}
		n = binary.BigEndian.Uint64(p[:])
	}
	if n > 16<<20 {
		return fixtureWireFrame{}, fmt.Errorf("fixture payload too large: %d", n)
	}
	var mask [4]byte
	if wantMasked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return fixtureWireFrame{}, err
		}
	}
	p := make([]byte, int(n))
	if _, err := io.ReadFull(r, p); err != nil {
		return fixtureWireFrame{}, err
	}
	if wantMasked {
		for i := range p {
			p[i] ^= mask[i%4]
		}
	}
	return fixtureWireFrame{h[0] & 0x0f, h[0]&0x80 != 0, p}, nil
}

type webSocketFixture struct {
	hits   atomic.Int64
	active atomic.Int64
	closes chan []byte
}

func (f *webSocketFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	if r.URL.Path == "/reject" {
		http.Error(w, "upstream denied", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/http" {
		_ = json.NewEncoder(w).Encode(map[string]string{"host": r.Host, "origin": r.Header.Get("Origin"), "for": r.Header.Get("X-Forwarded-For"), "proto": r.Header.Get("X-Forwarded-Proto"), "forwardedHost": r.Header.Get("X-Forwarded-Host"), "auth": r.Header.Get("Authorization"), "tunnAuth": r.Header.Get("Tunn-Authorization"), "cookie": r.Header.Get("Cookie")})
		return
	}
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	f.active.Add(1)
	defer f.active.Add(-1)
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	digest := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(digest[:])
	if r.URL.Path == "/bad-accept" {
		accept = "invalid"
	}
	_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n", accept)
	if r.Header.Get("Sec-WebSocket-Protocol") != "" {
		_, _ = rw.WriteString("Sec-WebSocket-Protocol: fixture-v1\r\n")
	}
	if r.Header.Get("Sec-WebSocket-Extensions") != "" {
		_, _ = rw.WriteString("Sec-WebSocket-Extensions: forbidden-extension\r\n")
	}
	_, _ = rw.WriteString("\r\n")
	_ = rw.Flush()
	if r.URL.Path == "/server-close" {
		_, _ = conn.Write(fixtureFrame(8, true, false, append([]byte{3, 232}, []byte("server goodbye")...)))
		// Wait for the closing reply, as a real WebSocket server does.
		frame, err := fixtureReadFrame(rw, true)
		if err == nil {
			select {
			case f.closes <- frame.payload:
			default:
			}
		}
		return
	}
	if r.URL.Path == "/server-ping" {
		_, _ = conn.Write(fixtureFrame(9, true, false, []byte("upstream ping")))
	}
	if r.URL.Path == "/server-pong" {
		_, _ = conn.Write(fixtureFrame(10, true, false, []byte("unsolicited pong")))
	}
	if r.URL.Path == "/oversize-response" {
		_, _ = conn.Write(fixtureFrame(2, true, false, make([]byte, 2048)))
	}
	if r.URL.Path == "/headers" {
		p, _ := json.Marshal(map[string]string{"host": r.Host, "origin": r.Header.Get("Origin"), "for": r.Header.Get("X-Forwarded-For"), "proto": r.Header.Get("X-Forwarded-Proto"), "forwardedHost": r.Header.Get("X-Forwarded-Host"), "auth": r.Header.Get("Authorization"), "tunnAuth": r.Header.Get("Tunn-Authorization"), "cookie": r.Header.Get("Cookie"), "uri": r.URL.RequestURI(), "extensions": r.Header.Get("Sec-WebSocket-Extensions")})
		_, _ = conn.Write(fixtureFrame(1, true, false, p))
	}
	for {
		frame, err := fixtureReadFrame(rw, true)
		if err != nil {
			return
		}
		if frame.opcode == 8 {
			select {
			case f.closes <- frame.payload:
			default:
			}
			_, _ = conn.Write(fixtureFrame(8, true, false, frame.payload))
			return
		}
		opcode := frame.opcode
		if opcode == 9 {
			opcode = 10
		}
		if frame.opcode == 10 {
			// Prove the client's pong was delivered upstream without consuming it
			// in the tunnel implementation.
			if r.URL.Path == "/server-ping" {
				opcode = 1
			} else {
				continue
			}
		}
		if _, err := conn.Write(fixtureFrame(opcode, frame.fin, false, frame.payload)); err != nil {
			return
		}
	}
}

type webSocketStack struct {
	relay         *httptest.Server
	publisher     *client.ServeClient
	tunnel        *TunnelConnection
	proxy         *ProxyServer
	fixture       *webSocketFixture
	cancel        context.CancelFunc
	transportDial func(context.Context, string, string) (net.Conn, error)
}

func startWebSocketStack(t *testing.T, configure func(*client.ServeClient)) *webSocketStack {
	t.Helper()
	fixture := &webSocketFixture{closes: make(chan []byte, 200)}
	var local *httptest.Server
	var localPipe, relayPipe *webSocketMemoryListener
	if *webSocketMemory {
		localPipe, relayPipe = newWebSocketMemoryListener("127.0.0.1:10080"), newWebSocketMemoryListener("127.0.0.1:10443")
		local = &httptest.Server{Listener: localPipe, Config: &http.Server{Handler: fixture}}
		local.Start()
	} else {
		local = httptest.NewServer(fixture)
	}
	cfg := &config.Config{PublicMode: true, Domain: "tunn.test", JWTSecret: "local-websocket-test-signing-key", NodeSecret: "local-cluster-secret"}
	server := NewTunnelServer(cfg, nil, nil, nil)
	gs := grpc.NewServer()
	pb.RegisterTunnelServiceServer(gs, server)
	proxy := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: server, grpcServer: gs, storage: storage.NewProxyStorage(), quotaCache: NewQuotaCache(time.Minute)}
	var relay *httptest.Server
	handler := proxy.createHTTP2Router(http.HandlerFunc(proxy.handleWebProxy))
	if *webSocketMemory {
		relay = &httptest.Server{Listener: relayPipe, Config: &http.Server{Handler: handler}}
	} else {
		relay = httptest.NewUnstartedServer(handler)
	}
	relay.EnableHTTP2 = true
	relay.StartTLS()
	ctx, cancel := context.WithCancel(context.Background())
	publisher := &client.ServeClient{TunnelID: "websocket-fixture", TargetURL: local.URL, ServerAddr: relay.Listener.Addr().String(), Insecure: true, InitialDelay: time.Millisecond, MaxReconnectDelay: 10 * time.Millisecond, WebSocket: &common.WebSocketOptions{IdleTimeout: 5 * time.Second, MaxMessageSize: 8 << 20}}
	var dial func(context.Context, string, string) (net.Conn, error)
	if *webSocketMemory {
		dial = func(ctx context.Context, _, address string) (net.Conn, error) {
			if address == relayPipe.Addr().String() {
				return relayPipe.Dial(ctx)
			}
			if address == localPipe.Addr().String() {
				return localPipe.Dial(ctx)
			}
			return nil, fmt.Errorf("unexpected fixture address %q", address)
		}
		publisher.DialContext = dial
		relay.Client().Transport.(*http.Transport).DialContext = dial
	}
	if configure != nil {
		configure(publisher)
	}
	done := make(chan error, 1)
	go func() { done <- publisher.Run(ctx) }()
	stack := &webSocketStack{relay: relay, publisher: publisher, proxy: proxy, fixture: fixture, cancel: cancel, transportDial: dial}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("publisher shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("publisher shutdown timed out")
		}
		gs.Stop()
		relay.Close()
		local.Close()
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if tunnel, ok := server.GetTunnel(publisher.TunnelID); ok {
			stack.tunnel = tunnel
			return stack
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("publisher failed to register")
	return nil
}
func (s *webSocketStack) cookie(t *testing.T, email string) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	if err := s.proxy.setAuthCookie(recorder, email); err != nil {
		t.Fatal(err)
	}
	cookie := recorder.Result().Cookies()[0]
	return cookie.Name + "=" + cookie.Value
}
func (s *webSocketStack) dial(path string, headers http.Header, early []byte) (net.Conn, *bufio.Reader, *http.Response, error) {
	var conn net.Conn
	var err error
	tlsOptions := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	if s.transportDial != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var raw net.Conn
		raw, err = s.transportDial(ctx, "tcp", s.relay.Listener.Addr().String())
		if err == nil {
			secure := tls.Client(raw, tlsOptions)
			err = secure.HandshakeContext(ctx)
			conn = secure
		}
	} else {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", s.relay.Listener.Addr().String(), tlsOptions)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request, _ := http.NewRequest(http.MethodGet, s.relay.URL+path, nil)
	request.Host = "websocket-fixture.tunn.test"
	request.Header = headers.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "keep-alive, Upgrade")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if err = request.Write(conn); err == nil && early != nil {
		_, err = conn.Write(early)
	}
	reader := bufio.NewReader(conn)
	var response *http.Response
	if err == nil {
		response, err = http.ReadResponse(reader, request)
	}
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	return conn, reader, response, nil
}
func mustWebSocket(t *testing.T, s *webSocketStack, path string, headers http.Header) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, reader, response, err := s.dial(path, headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		_ = conn.Close()
		t.Fatalf("upgrade status %d", response.StatusCode)
	}
	if response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal("incorrect handshake accept")
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, reader
}
func expectWireFrame(t *testing.T, r io.Reader, opcode byte, payload []byte) {
	t.Helper()
	frame, err := fixtureReadFrame(r, false)
	if err != nil {
		t.Fatal(err)
	}
	if frame.opcode != opcode || !bytes.Equal(frame.payload, payload) {
		t.Fatalf("frame opcode=%d bytes=%d; want opcode=%d bytes=%d", frame.opcode, len(frame.payload), opcode, len(payload))
	}
}
func waitWebSocketsClosed(t *testing.T, s *webSocketStack) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.tunnel.pendingMu.RLock()
		n := len(s.tunnel.pendingStreams)
		s.tunnel.pendingMu.RUnlock()
		if n == 0 && s.fixture.active.Load() == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("WebSocket resources did not close")
}

func TestWebSocketEchoAcrossTLSRelay(t *testing.T) {
	s := startWebSocketStack(t, nil)
	conn, reader := mustWebSocket(t, s, "/echo", nil)
	for _, test := range []struct {
		opcode  byte
		payload []byte
	}{{1, []byte("text hello")}, {2, []byte{0, 255, 1, 128}}, {2, bytes.Repeat([]byte{0xab}, 1<<20)}} {
		if _, err := conn.Write(fixtureFrame(test.opcode, true, true, test.payload)); err != nil {
			t.Fatal(err)
		}
		expectWireFrame(t, reader, test.opcode, test.payload)
	}
	// Control frames interleave with a fragmented data message.
	for _, frame := range []struct {
		opcode  byte
		fin     bool
		payload []byte
	}{{1, false, []byte("first")}, {9, true, []byte("client ping")}, {0, true, []byte("last")}} {
		_, err := conn.Write(fixtureFrame(frame.opcode, frame.fin, true, frame.payload))
		if err != nil {
			t.Fatal(err)
		}
		expected := frame.opcode
		if expected == 9 {
			expected = 10
		}
		got, err := fixtureReadFrame(reader, false)
		if err != nil {
			t.Fatalf("reading fragment/control opcode %d: %v", frame.opcode, err)
		}
		if got.opcode != expected || got.fin != frame.fin || !bytes.Equal(got.payload, frame.payload) {
			t.Fatalf("fragment/control changed: %#v", got)
		}
	}
	closePayload := append([]byte{3, 232}, []byte("client goodbye")...)
	_, _ = conn.Write(fixtureFrame(8, true, true, closePayload))
	expectWireFrame(t, reader, 8, closePayload)
	select {
	case got := <-s.fixture.closes:
		if !bytes.Equal(got, closePayload) {
			t.Fatal("close payload changed")
		}
	case <-time.After(time.Second):
		t.Fatal("client close did not reach upstream")
	}
	waitWebSocketsClosed(t, s)
}
func TestWebSocketServerControlsAndClose(t *testing.T) {
	s := startWebSocketStack(t, nil)
	conn, reader := mustWebSocket(t, s, "/server-ping", nil)
	expectWireFrame(t, reader, 9, []byte("upstream ping"))
	_, _ = conn.Write(fixtureFrame(10, true, true, []byte("upstream ping")))
	expectWireFrame(t, reader, 1, []byte("upstream ping"))
	_ = conn.Close()
	pongConn, pongReader := mustWebSocket(t, s, "/server-pong", nil)
	reader = pongReader
	expectWireFrame(t, reader, 10, []byte("unsolicited pong"))
	_ = pongConn.Close()
	conn, reader = mustWebSocket(t, s, "/server-close", nil)
	expectWireFrame(t, reader, 8, append([]byte{3, 232}, []byte("server goodbye")...))
	_, _ = conn.Write(fixtureFrame(8, true, true, []byte{3, 232}))
	select {
	case payload := <-s.fixture.closes:
		if !bytes.Equal(payload, []byte{3, 232}) {
			t.Fatal("server close reply changed")
		}
	case <-time.After(time.Second):
		t.Fatal("server close reply not propagated")
	}
	waitWebSocketsClosed(t, s)
}
func TestWebSocketBufferedUpgradeFrames(t *testing.T) {
	s := startWebSocketStack(t, nil)
	conn, reader, response, err := s.dial("/echo", nil, fixtureFrame(1, true, true, []byte("early frame")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if response.StatusCode != 101 {
		t.Fatalf("status %d", response.StatusCode)
	}
	expectWireFrame(t, reader, 1, []byte("early frame"))
}
func TestWebSocketConcurrentSockets(t *testing.T) {
	s := startWebSocketStack(t, nil)
	var sockets []net.Conn
	var readers []*bufio.Reader
	for i := 0; i < 100; i++ {
		conn, reader := mustWebSocket(t, s, "/echo", nil)
		sockets = append(sockets, conn)
		readers = append(readers, reader)
	}
	conn, _, response, err := s.dial("/echo", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if response.StatusCode != 502 {
		t.Fatalf("over-limit upgrade=%d", response.StatusCode)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 100)
	for i, conn := range sockets {
		wg.Add(1)
		go func(i int, conn net.Conn) {
			defer wg.Done()
			p := []byte(fmt.Sprintf("socket-%d", i))
			if _, err := conn.Write(fixtureFrame(1, true, true, p)); err != nil {
				failures <- err
				return
			}
			frame, err := fixtureReadFrame(readers[i], false)
			if err != nil {
				failures <- err
				return
			}
			if frame.opcode != 1 || !bytes.Equal(frame.payload, p) {
				failures <- fmt.Errorf("crossed socket %d", i)
			}
			_ = conn.Close()
		}(i, conn)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	waitWebSocketsClosed(t, s)
	conn, reader := mustWebSocket(t, s, "/echo", nil)
	_, _ = conn.Write(fixtureFrame(1, true, true, []byte("slot reused")))
	expectWireFrame(t, reader, 1, []byte("slot reused"))
}
func TestWebSocketUpgradeAuthenticationAndHeaders(t *testing.T) {
	s := startWebSocketStack(t, func(p *client.ServeClient) { p.AllowedEmails = []string{"alice@example.com"} })
	for _, test := range []struct {
		cookie string
		status int
	}{{"", 401}, {authCookieName + "=invalid", 401}, {s.cookie(t, "mallory@example.com"), 403}} {
		conn, _, response, err := s.dial("/headers", http.Header{"Cookie": {test.cookie}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if response.StatusCode != test.status {
			t.Fatalf("auth status %d, want %d", response.StatusCode, test.status)
		}
	}
	if s.fixture.hits.Load() != 0 {
		t.Fatal("denied upgrade reached upstream")
	}
	headers := http.Header{"Cookie": {s.cookie(t, "alice@example.com") + "; app_session=kept"}, "Origin": {"https://websocket-fixture.tunn.test"}, "Authorization": {"Bearer application-secret"}, "Tunn-Authorization": {"Bearer must-not-leak"}, "X-Forwarded-For": {"spoofed"}, "X-Forwarded-Proto": {"spoofed"}, "X-Forwarded-Host": {"spoofed"}, "Sec-Websocket-Protocol": {"fixture-v1"}, "Sec-Websocket-Extensions": {"permessage-deflate"}}
	_, reader := mustWebSocket(t, s, "/headers?tenant=one", headers)
	frame, err := fixtureReadFrame(reader, false)
	if err != nil {
		t.Fatal(err)
	}
	var seen map[string]string
	if err = json.Unmarshal(frame.payload, &seen); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"host": "websocket-fixture.tunn.test", "origin": "https://websocket-fixture.tunn.test", "for": "127.0.0.1", "proto": "https", "forwardedHost": "websocket-fixture.tunn.test", "auth": "Bearer application-secret", "tunnAuth": "", "cookie": "app_session=kept", "uri": "/headers?tenant=one", "extensions": ""} {
		if seen[key] != want {
			t.Errorf("%s=%q, want %q", key, seen[key], want)
		}
	}
}
func TestWebSocketBearerHTTPRotationAndRevocation(t *testing.T) {
	t.Setenv("TUNN_CONFIG_DIR", t.TempDir())
	token, digest, err := client.GenerateEndpointToken()
	if err != nil {
		t.Fatal(err)
	}
	path, err := client.SaveEndpointToken("websocket-fixture", token)
	if err != nil {
		t.Fatal(err)
	}
	// No allow-list still requires the explicitly enabled endpoint capability.
	s := startWebSocketStack(t, func(p *client.ServeClient) { p.AccessTokenSHA256 = digest; p.EndpointTokenPath = path })
	conn, _, response, err := s.dial("/headers", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if response.StatusCode != 401 {
		t.Fatalf("bearer endpoint is open: %d", response.StatusCode)
	}
	tokenHeaders := http.Header{"Tunn-Authorization": {"Bearer " + token}, "Authorization": {"Bearer upstream-token"}}
	old, reader := mustWebSocket(t, s, "/headers", tokenHeaders)
	frame, err := fixtureReadFrame(reader, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(frame.payload), "upstream-token") || strings.Contains(string(frame.payload), token) {
		t.Fatalf("token stripping failed: %s", frame.payload)
	}
	// The standard Authorization fallback is consumed as a tunn credential.
	fallback, fallbackReader := mustWebSocket(t, s, "/headers", http.Header{"Authorization": {"Bearer " + token}})
	frame, err = fixtureReadFrame(fallbackReader, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(frame.payload), token) {
		t.Fatal("Authorization fallback leaked")
	}
	_ = fallback.Close()
	request, _ := http.NewRequest(http.MethodGet, s.relay.URL+"/http", nil)
	request.Host = "websocket-fixture.tunn.test"
	request.Header = tokenHeaders.Clone()
	result, err := s.relay.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(result.Body)
	_ = result.Body.Close()
	if result.StatusCode != 200 || strings.Contains(string(body), token) || !strings.Contains(string(body), "upstream-token") {
		t.Fatalf("bearer HTTP response: %d %s", result.StatusCode, body)
	}
	cookieConn, cookieReader := mustWebSocket(t, s, "/echo", http.Header{"Cookie": {s.cookie(t, s.tunnel.CreatorEmail)}})
	rotated, _, err := client.RotateEndpointToken("websocket-fixture")
	if err != nil {
		t.Fatal(err)
	}
	newDigest := sha256.Sum256([]byte(rotated))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !bytes.Equal(s.tunnel.accessTokenDigest(), newDigest[:]) {
		time.Sleep(10 * time.Millisecond)
	}
	if !bytes.Equal(s.tunnel.accessTokenDigest(), newDigest[:]) {
		t.Fatal("token watcher did not rotate relay digest")
	}
	_ = old.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("old bearer WebSocket survived revocation")
	}
	_ = old.Close()
	_, _ = cookieConn.Write(fixtureFrame(1, true, true, []byte("cookie unaffected")))
	expectWireFrame(t, cookieReader, 1, []byte("cookie unaffected"))
	for _, token := range []string{token, "tunn_ep_wrong"} {
		conn, _, response, err = s.dial("/echo", http.Header{"Tunn-Authorization": {"Bearer " + token}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if response.StatusCode != 401 {
			t.Fatalf("revoked/wrong token status %d", response.StatusCode)
		}
	}
	_, _ = mustWebSocket(t, s, "/echo", http.Header{"Tunn-Authorization": {"Bearer " + rotated}})
}
func TestWebSocketIdleAndKeepalive(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		s := startWebSocketStack(t, func(p *client.ServeClient) {
			p.WebSocket = &common.WebSocketOptions{IdleTimeout: 80 * time.Millisecond, MaxMessageSize: 8 << 20}
		})
		_, reader := mustWebSocket(t, s, "/echo", nil)
		expectWireFrame(t, reader, 8, []byte{3, 233}) // 1001
		waitWebSocketsClosed(t, s)
	})
	t.Run("keepalive", func(t *testing.T) {
		s := startWebSocketStack(t, func(p *client.ServeClient) {
			p.WebSocket = &common.WebSocketOptions{IdleTimeout: 200 * time.Millisecond, KeepaliveInterval: 30 * time.Millisecond, MaxMessageSize: 8 << 20}
		})
		conn, reader := mustWebSocket(t, s, "/echo", nil)
		deadline := time.Now().Add(450 * time.Millisecond)
		for time.Now().Before(deadline) {
			frame, err := fixtureReadFrame(reader, false)
			if err != nil {
				t.Fatal(err)
			}
			if frame.opcode == 9 {
				_, _ = conn.Write(fixtureFrame(10, true, true, frame.payload))
			} else if frame.opcode != 10 {
				t.Fatalf("unexpected keepalive frame %d", frame.opcode)
			}
		}
		_ = conn.Close()
		waitWebSocketsClosed(t, s)
	})
}
func TestWebSocketMessageLimits(t *testing.T) {
	for _, path := range []string{"/echo", "/oversize-response"} {
		t.Run(path, func(t *testing.T) {
			s := startWebSocketStack(t, func(p *client.ServeClient) {
				p.WebSocket = &common.WebSocketOptions{IdleTimeout: time.Second, MaxMessageSize: 1024}
			})
			conn, reader := mustWebSocket(t, s, path, nil)
			if path == "/echo" {
				// Individually legal fragments must count toward one total message limit.
				p := make([]byte, 700)
				_, _ = conn.Write(fixtureFrame(2, false, true, p))
				expectWireFrame(t, reader, 2, p)
				_, _ = conn.Write(fixtureFrame(0, true, true, p))
			}
			expectWireFrame(t, reader, 8, []byte{3, 241}) // 1009
			waitWebSocketsClosed(t, s)
		})
	}
}
func TestWebSocketFailedUpgradesAndPublisherShutdown(t *testing.T) {
	s := startWebSocketStack(t, nil)
	for _, test := range []struct {
		path   string
		status int
	}{{"/reject", 403}, {"/bad-accept", 502}} {
		conn, _, response, err := s.dial(test.path, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if response.StatusCode != test.status {
			t.Fatalf("%s: %d", test.path, response.StatusCode)
		}
	}
	conn, reader := mustWebSocket(t, s, "/echo", nil)
	s.cancel()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("publisher shutdown did not close socket")
	}
	waitWebSocketsClosed(t, s)
}
func TestWebSocketRequireUpstreamAuth(t *testing.T) {
	token, digest, err := client.GenerateEndpointToken()
	if err != nil {
		t.Fatal(err)
	}
	s := startWebSocketStack(t, func(p *client.ServeClient) { p.RequireUpstreamAuth = true; p.AccessTokenSHA256 = digest })
	headers := http.Header{"Tunn-Authorization": {"Bearer " + token}}
	conn, _, response, err := s.dial("/echo", headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if response.StatusCode != 401 {
		t.Fatalf("upstream auth guard status %d", response.StatusCode)
	}
	if s.fixture.hits.Load() != 0 {
		t.Fatal("upstream auth guard contacted target")
	}
	headers.Set("Authorization", "Bearer upstream-token")
	_, _ = mustWebSocket(t, s, "/echo", headers)
}

var webSocketMemory = flag.Bool("websocket-memory", false, "run WebSocket fixtures on in-memory net.Pipe connections")

type webSocketMemoryAddress string

func (a webSocketMemoryAddress) Network() string { return "tcp" }
func (a webSocketMemoryAddress) String() string  { return string(a) }

type webSocketMemoryListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
	address     webSocketMemoryAddress
}

func newWebSocketMemoryListener(address string) *webSocketMemoryListener {
	return &webSocketMemoryListener{connections: make(chan net.Conn), done: make(chan struct{}), address: webSocketMemoryAddress(address)}
}
func (l *webSocketMemoryListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *webSocketMemoryListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *webSocketMemoryListener) Addr() net.Addr { return l.address }
func (l *webSocketMemoryListener) Dial(ctx context.Context) (net.Conn, error) {
	a, b := net.Pipe()
	select {
	case l.connections <- webSocketMemoryConn{b}:
		return webSocketMemoryConn{a}, nil
	case <-l.done:
		_ = a.Close()
		_ = b.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = a.Close()
		_ = b.Close()
		return nil, ctx.Err()
	}
}

type webSocketMemoryConn struct{ net.Conn }

func (c webSocketMemoryConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
}

func TestWebSocketPartialFrameIdle(t *testing.T) {
	s := startWebSocketStack(t, func(p *client.ServeClient) {
		p.WebSocket = &common.WebSocketOptions{IdleTimeout: 80 * time.Millisecond, MaxMessageSize: 1024}
	})
	conn, reader := mustWebSocket(t, s, "/echo", nil)
	wire := fixtureFrame(2, true, true, make([]byte, 1024))
	_, _ = conn.Write(wire[:200])
	expectWireFrame(t, reader, 8, []byte{3, 233})
	waitWebSocketsClosed(t, s)
}
func TestWebSocketBearerDisabledAndUpstreamHTTPGuard(t *testing.T) {
	token, _, err := client.GenerateEndpointToken()
	if err != nil {
		t.Fatal(err)
	}
	s := startWebSocketStack(t, func(p *client.ServeClient) {
		p.AllowedEmails = []string{"alice@example.com"}
		p.RequireUpstreamAuth = true
	})
	conn, _, response, err := s.dial("/echo", http.Header{"Tunn-Authorization": {"Bearer " + token}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if response.StatusCode != 401 {
		t.Fatalf("bearer is enabled without opt-in: %d", response.StatusCode)
	}
	request, _ := http.NewRequest(http.MethodGet, s.relay.URL+"/http", nil)
	request.Host = "websocket-fixture.tunn.test"
	request.Header.Set("Cookie", s.cookie(t, "alice@example.com"))
	response, err = s.relay.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 401 || s.fixture.hits.Load() != 0 {
		t.Fatal("HTTP upstream auth guard failed")
	}
	request.Header.Set("Authorization", "Bearer application-token")
	response, err = s.relay.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || !strings.Contains(string(body), "application-token") || strings.Contains(string(body), authCookieName) {
		t.Fatalf("guarded HTTP: %d %s", response.StatusCode, body)
	}
	// Subprotocol values are case-sensitive and must be offered exactly.
	conn, _, response, err = s.dial("/echo", http.Header{"Cookie": {s.cookie(t, "alice@example.com")}, "Authorization": {"Bearer application-token"}, "Sec-Websocket-Protocol": {"Fixture-V1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if response.StatusCode != 502 {
		t.Fatalf("unrequested subprotocol accepted: %d", response.StatusCode)
	}
}
