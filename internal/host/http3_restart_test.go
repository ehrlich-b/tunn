package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// Run the real listener in a separate process, so a crash loses all connection
// state without giving the old process a chance to send CONNECTION_CLOSE.
func TestHTTP3Process(t *testing.T) {
	if os.Getenv("TUNN_TEST_H3_PROCESS") != "1" {
		t.Skip("subprocess helper")
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv("TUNN_TEST_H3_CERT"), os.Getenv("TUNN_TEST_H3_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	p := &ProxyServer{
		HTTP3Addr: os.Getenv("TUNN_TEST_H3_ADDR"),
		config:    &config.Config{JWTSecret: "fixture-signing-secret"},
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	if os.Getenv("TUNN_TEST_H3_TLS_SECRET") == "1" {
		p.config.JWTSecret = ""
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stuck" {
			_, _ = io.WriteString(w, "started\n")
			w.(http.Flusher).Flush()
			select {} // Deliberately ignore request cancellation.
		}
		if r.URL.Path == "/drain" {
			_, _ = io.WriteString(w, "before\n")
			w.(http.Flusher).Flush()
			<-ctx.Done()
			_, _ = io.WriteString(w, "after\n")
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	done := make(chan error, 1)
	go func() {
		if os.Getenv("TUNN_TEST_H3_LEGACY") == "1" {
			// Mint an early-data-capable ticket like the previous HTTP/3 policy.
			key, err := p.http3ResetKey()
			if err != nil {
				done <- err
				return
			}
			socket, err := net.ListenPacket("udp", p.HTTP3Addr)
			if err != nil {
				done <- err
				return
			}
			defer socket.Close()
			transport := &quic.Transport{Conn: socket, StatelessResetKey: &key}
			defer transport.Close()
			listener, err := transport.ListenEarly(http3.ConfigureTLSConfig(p.tlsConfig), &quic.Config{Allow0RTT: true})
			if err != nil {
				done <- err
				return
			}
			defer listener.Close()
			server := &http3.Server{Handler: handler}
			defer server.Close()
			p.listenerStarted(listenerHTTP3)
			done <- server.ServeListener(listener)
			return
		}
		done <- p.startHTTP3Server(ctx, handler)
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for p.listenerState.Load()&listenerHTTP3 == 0 {
		select {
		case err := <-done:
			t.Fatalf("listener startup: %v", err)
		case <-ticker.C:
		}
	}
	fmt.Println("HTTP3_READY")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type http3Process struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error // Read only after done is closed.
}

func startHTTP3Process(t *testing.T, p *ProxyServer, legacy bool) *http3Process {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHTTP3Process$", "-test.timeout=20s")
	cmd.Env = append(os.Environ(), "TUNN_TEST_H3_PROCESS=1", "TUNN_TEST_H3_ADDR="+p.HTTP3Addr,
		"TUNN_TEST_H3_CERT="+p.CertFile, "TUNN_TEST_H3_KEY="+p.KeyFile,
		fmt.Sprintf("TUNN_TEST_H3_TLS_SECRET=%d", map[bool]int{false: 0, true: 1}[p.config.JWTSecret == ""]),
		fmt.Sprintf("TUNN_TEST_H3_LEGACY=%d", map[bool]int{false: 0, true: 1}[legacy]))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	process := &http3Process{cmd: cmd, done: make(chan struct{})}
	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "HTTP3_READY" {
				close(ready)
			}
		}
	}()
	go func() { process.err = cmd.Wait(); close(process.done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		process.wait(t)
	})
	select {
	case <-ready:
	case <-process.done:
		t.Fatalf("HTTP/3 process exited before readiness: %v", process.err)
	case <-time.After(10 * time.Second):
		t.Fatal("HTTP/3 process not ready")
	}
	return process
}

func (p *http3Process) wait(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		t.Fatal("HTTP/3 process did not exit")
	}
}

func dialHTTP3(t *testing.T, addr string, tlsConfig *tls.Config, early bool) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	var conn *quic.Conn
	var err error
	if early {
		conn, err = quic.DialAddrEarly(ctx, addr, tlsConfig, nil)
	} else {
		conn, err = quic.DialAddr(ctx, addr, tlsConfig, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	return conn
}

func http3Request(ctx context.Context, addr string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+addr+"/healthz", nil)
	// A reset may only answer a packet larger than the minimum reset size.
	req.Header.Set("X-Restart-Probe", strings.Repeat("request-after-restart", 16))
	return req
}

func checkHTTP3Response(t *testing.T, client *http3.ClientConn, addr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := client.RoundTrip(http3Request(ctx, addr))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "ok" || response.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 response: status=%d body=%q err=%v", response.StatusCode, body, err)
	}
}

func TestHTTP3CrashRestartResetsOldConnection(t *testing.T) {
	for _, source := range []string{"jwt", "tls"} {
		t.Run(source, func(t *testing.T) { testHTTP3CrashRestart(t, source) })
	}
}

func testHTTP3CrashRestart(t *testing.T, source string) {
	p, http2Client, _ := opsProxy(t)
	if source == "tls" {
		p.config.JWTSecret = ""
	}
	first := startHTTP3Process(t, p, false)
	tlsConfig := http2Client.Transport.(*http.Transport).TLSClientConfig
	conn := dialHTTP3(t, p.HTTP3Addr, tlsConfig, false)
	transport := &http3.Transport{}
	client := transport.NewClientConn(conn)
	checkHTTP3Response(t, client, p.HTTP3Addr)
	if err := first.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	first.wait(t)
	startHTTP3Process(t, p, false)
	if conn.Context().Err() != nil {
		t.Fatal("old connection closed before sending restart probe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	start := time.Now()
	response, err := client.RoundTrip(http3Request(ctx, p.HTTP3Addr))
	if response != nil {
		_ = response.Body.Close()
	}
	var reset *quic.StatelessResetError
	if !errors.As(err, &reset) || time.Since(start) >= 750*time.Millisecond {
		t.Fatalf("old connection did not reset quickly: elapsed=%s err=%v", time.Since(start), err)
	}
	t.Logf("old connection received stateless reset in %s", time.Since(start))
	fresh := dialHTTP3(t, p.HTTP3Addr, tlsConfig, false)
	checkHTTP3Response(t, transport.NewClientConn(fresh), p.HTTP3Addr)
}

func TestHTTP3SIGTERMGoAwayAndConnectionClose(t *testing.T) {
	p, http2Client, _ := opsProxy(t)
	process := startHTTP3Process(t, p, false)
	conn := dialHTTP3(t, p.HTTP3Addr, http2Client.Transport.(*http.Transport).TLSClientConfig, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// A minimal HTTP/3 peer lets us inspect the actual wire GOAWAY and keep
	// the connection open until the server's drain deadline forces a close.
	control, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.Write([]byte{0, 4, 0}); err != nil { // control stream, empty SETTINGS
		t.Fatal(err)
	}
	serverControl, err := conn.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = serverControl.SetReadDeadline(time.Now().Add(time.Second))
	reader := quicvarint.NewReader(serverControl)
	streamType, err := quicvarint.Read(reader)
	if err != nil || streamType != 0 {
		t.Fatalf("server control stream type=%d err=%v", streamType, err)
	}
	readFrame := func() uint64 {
		t.Helper()
		typ, err := quicvarint.Read(reader)
		if err != nil {
			t.Fatal(err)
		}
		length, err := quicvarint.Read(reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
			t.Fatal(err)
		}
		return typ
	}
	if typ := readFrame(); typ != 4 {
		t.Fatalf("first frame = %d, want SETTINGS", typ)
	}
	start := time.Now()
	if err := process.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if typ := readFrame(); typ != 7 { // GOAWAY
		t.Fatalf("shutdown frame = %d, want GOAWAY", typ)
	}
	if elapsed := time.Since(start); elapsed >= 750*time.Millisecond {
		t.Fatalf("GOAWAY delayed by %s", elapsed)
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(http3DrainTimeout + time.Second):
		t.Fatal("no CONNECTION_CLOSE within drain bound")
	}
	var appErr *quic.ApplicationError
	if !errors.As(context.Cause(conn.Context()), &appErr) || !appErr.Remote || appErr.ErrorCode != quic.ApplicationErrorCode(http3.ErrCodeNoError) {
		t.Fatalf("expected remote H3_NO_ERROR CONNECTION_CLOSE, got %v", context.Cause(conn.Context()))
	}
	if elapsed := time.Since(start); elapsed > http3DrainTimeout+750*time.Millisecond {
		t.Fatalf("CONNECTION_CLOSE delayed by %s", elapsed)
	}
	process.wait(t)
	if process.err != nil {
		t.Fatalf("SIGTERM exit: %v", process.err)
	}
	t.Logf("received wire GOAWAY and remote CONNECTION_CLOSE; process exited cleanly")
}

func TestHTTP3SIGTERMDrainsActiveRequest(t *testing.T) {
	p, http2Client, _ := opsProxy(t)
	process := startHTTP3Process(t, p, false)
	conn := dialHTTP3(t, p.HTTP3Addr, http2Client.Transport.(*http.Transport).TLSClientConfig, false)
	transport := &http3.Transport{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://"+p.HTTP3Addr+"/drain", nil)
	response, err := transport.NewClientConn(conn).RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if err := process.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "before\nafter\n" {
		t.Fatalf("shutdown interrupted active request: body=%q err=%v", body, err)
	}
	process.wait(t)
	if process.err != nil {
		t.Fatalf("SIGTERM exit: %v", process.err)
	}
}

func TestHTTP3SIGTERMBoundsUnresponsiveHandler(t *testing.T) {
	p, http2Client, _ := opsProxy(t)
	process := startHTTP3Process(t, p, false)
	conn := dialHTTP3(t, p.HTTP3Addr, http2Client.Transport.(*http.Transport).TLSClientConfig, false)
	transport := &http3.Transport{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://"+p.HTTP3Addr+"/stuck", nil)
	response, err := transport.NewClientConn(conn).RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	start := time.Now()
	if err := process.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(response.Body)
	if err == nil {
		t.Fatal("stuck response completed without a connection error")
	}
	var appErr *quic.ApplicationError
	if !errors.As(context.Cause(conn.Context()), &appErr) || !appErr.Remote || appErr.ErrorCode != quic.ApplicationErrorCode(http3.ErrCodeNoError) {
		t.Fatalf("expected remote CONNECTION_CLOSE for stuck request, got %v (body error: %v)", context.Cause(conn.Context()), err)
	}
	if elapsed := time.Since(start); elapsed > http3DrainTimeout+750*time.Millisecond {
		t.Fatalf("unresponsive handler delayed CONNECTION_CLOSE by %s", elapsed)
	}
	process.wait(t)
	if process.err != nil {
		t.Fatalf("unresponsive handler prevented clean SIGTERM exit: %v", process.err)
	}
	t.Log("unresponsive handler did not prevent CONNECTION_CLOSE or clean process exit")
}

type http3TicketCache struct {
	tls.ClientSessionCache
	stored chan *tls.ClientSessionState
}

func (c *http3TicketCache) Put(key string, state *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, state)
	if state != nil {
		select {
		case c.stored <- state:
		default:
		}
	}
}

func TestHTTP3RestartRejectsLegacyEarlyDataTicket(t *testing.T) {
	p, http2Client, _ := opsProxy(t)
	legacy := startHTTP3Process(t, p, true)
	tlsConfig := http2Client.Transport.(*http.Transport).TLSClientConfig.Clone()
	cache := &http3TicketCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), stored: make(chan *tls.ClientSessionState, 4)}
	tlsConfig.ClientSessionCache = cache
	conn := dialHTTP3(t, p.HTTP3Addr, tlsConfig, false)
	transport := &http3.Transport{}
	checkHTTP3Response(t, transport.NewClientConn(conn), p.HTTP3Addr)
	select {
	case ticket := <-cache.stored:
		_, state, err := ticket.ResumptionState()
		if err != nil || !state.EarlyData {
			t.Fatalf("legacy ticket must allow early data: state=%v err=%v", state, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("legacy server did not issue a session ticket")
	}
	_ = legacy.cmd.Process.Kill()
	legacy.wait(t)
	startHTTP3Process(t, p, false)
	start := time.Now()
	fresh := dialHTTP3(t, p.HTTP3Addr, tlsConfig, true)
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	// Attempt an early control stream with the cached ticket. On rejection,
	// quic-go resets its stream maps before normal HTTP/3 can use them.
	early, err := fresh.OpenUniStreamSync(ctx)
	if err == nil {
		_, err = early.Write([]byte{0, 4, 0})
	}
	if err != nil && !errors.Is(err, quic.Err0RTTRejected) {
		t.Fatal(err)
	}
	fresh, err = fresh.NextConnection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkHTTP3Response(t, transport.NewClientConn(fresh), p.HTTP3Addr)
	state := fresh.ConnectionState()
	if state.Used0RTT || state.TLS.DidResume || time.Since(start) >= 750*time.Millisecond {
		t.Fatalf("old ticket did not promptly fall back to full handshake: elapsed=%s resumed=%t early=%t", time.Since(start), state.TLS.DidResume, state.Used0RTT)
	}
	t.Logf("legacy early-data ticket rejected; full handshake and HTTP/3 request in %s", time.Since(start))
}
