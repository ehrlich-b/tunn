package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type originPoolSession struct {
	stream *isolationStream
	cancel context.CancelFunc
	done   chan error
	next   int
}

func startOriginPoolSession(t *testing.T, client *ServeClient) *originPoolSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &isolationStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 16), outgoing: make(chan *pb.TunnelMessage, 16)}
	session := &originPoolSession{stream: stream, cancel: cancel, done: make(chan error, 1)}
	go func() { session.done <- client.ServeMessages(ctx, stream) }()
	t.Cleanup(func() { session.stop(t) })
	return session
}

func (s *originPoolSession) stop(t *testing.T) {
	t.Helper()
	if s.cancel == nil {
		return
	}
	s.cancel()
	s.cancel = nil
	select {
	case err := <-s.done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("publisher shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not shut down")
	}
}

func (s *originPoolSession) request(t *testing.T, streaming bool) {
	t.Helper()
	s.next++
	id := fmt.Sprintf("request-%d", s.next)
	if streaming {
		s.stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: &pb.ConnectionOpen{
			ConnectionId: id, Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/"},
		}}}
		s.stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id}}}
	} else {
		s.stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: id, Method: "GET", Path: "/"}}}
	}
	body := ""
	accepted := false
	for {
		select {
		case msg := <-s.stream.outgoing:
			switch {
			case msg.GetHttpResponse() != nil:
				r := msg.GetHttpResponse()
				if streaming || r.ConnectionId != id || r.StatusCode != 200 || string(r.Body) != "origin response" {
					t.Fatalf("unexpected buffered response: %v", r)
				}
				return
			case msg.GetConnectionAccept() != nil:
				r := msg.GetConnectionAccept()
				if !streaming || r.ConnectionId != id || !r.Success || r.GetHttpResponse().GetStatusCode() != 200 {
					t.Fatalf("unexpected streaming response: %v", r)
				}
				accepted = true
			case msg.GetConnectionData() != nil:
				body += string(msg.GetConnectionData().Data)
			case msg.GetConnectionHalfClose() != nil:
				if !accepted || msg.GetConnectionHalfClose().ConnectionId != id || body != "origin response" {
					t.Fatalf("unexpected streaming completion: %v, body %q", msg, body)
				}
				return
			default:
				t.Fatalf("unexpected origin message: %v", msg)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("origin request did not complete")
		}
	}
}

func newOriginPoolServer(t *testing.T, protocol string) (*httptest.Server, *atomic.Int32, <-chan struct{}) {
	t.Helper()
	var accepted atomic.Int32
	closed := make(chan struct{}, 128)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "origin response")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			accepted.Add(1)
		case http.StateClosed:
			closed <- struct{}{}
		}
	}
	if protocol == "http" {
		server.Start()
	} else {
		server.EnableHTTP2 = protocol == "http2"
		server.StartTLS()
	}
	t.Cleanup(server.Close)
	return server, &accepted, closed
}

func TestOriginPoolSequentialReuse(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			server, accepted, _ := newOriginPoolServer(t, "http")
			session := startOriginPoolSession(t, &ServeClient{TargetURL: server.URL})
			for i := 0; i < 3; i++ {
				session.request(t, mode == "streaming" || mode == "mixed" && i%2 != 0)
			}
			if got := accepted.Load(); got != 1 {
				t.Fatalf("origin accepted %d sockets for 3 sequential requests, want 1", got)
			}
		})
	}
}

func waitOriginPoolClosed(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("publisher retained an idle origin socket after shutdown")
	}
}

func TestOriginPoolPublisherIsolationAndCancellation(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			server, accepted, closed := newOriginPoolServer(t, "http")
			client := &ServeClient{TargetURL: server.URL}
			first := startOriginPoolSession(t, client)
			second := startOriginPoolSession(t, &ServeClient{TargetURL: server.URL})
			for i := 0; i < 2; i++ {
				first.request(t, streaming)
				second.request(t, streaming)
			}
			if got := accepted.Load(); got != 2 {
				t.Fatalf("two publishers accepted %d origin sockets, want 2", got)
			}
			select {
			case <-closed:
				t.Fatal("origin socket closed before publisher shutdown")
			default:
			}
			first.stop(t)
			waitOriginPoolClosed(t, closed)
			second.request(t, streaming)
			if got := accepted.Load(); got != 2 {
				t.Fatalf("canceling one publisher disturbed the other's pool: %d sockets", got)
			}
			second.stop(t)
			waitOriginPoolClosed(t, closed)
			// Reusing a ServeClient for a new publication must own a new pool.
			restarted := startOriginPoolSession(t, client)
			restarted.request(t, streaming)
			if got := accepted.Load(); got != 3 {
				t.Fatalf("restarted publisher accepted %d sockets, want 3", got)
			}
			restarted.stop(t)
			waitOriginPoolClosed(t, closed)
		})
	}
}

func TestOriginPoolHTTPSReuse(t *testing.T) {
	for _, protocol := range []string{"https", "http2"} {
		t.Run(protocol, func(t *testing.T) {
			server, accepted, closed := newOriginPoolServer(t, protocol)
			session := startOriginPoolSession(t, &ServeClient{TargetURL: server.URL, LocalTLSConfig: server.Client().Transport.(*http.Transport).TLSClientConfig})
			for i := 0; i < 4; i++ {
				session.request(t, i%2 == 0)
			}
			if got := accepted.Load(); got != 1 {
				t.Fatalf("%s accepted %d sockets, want 1", protocol, got)
			}
			session.stop(t)
			waitOriginPoolClosed(t, closed)
		})
	}
}

func TestOriginPoolDialIsolation(t *testing.T) {
	firstServer, firstAccepted, _ := newOriginPoolServer(t, "http")
	secondServer, secondAccepted, _ := newOriginPoolServer(t, "http")
	var firstDials, secondDials atomic.Int32
	newClient := func(server *httptest.Server, dials *atomic.Int32) *ServeClient {
		return &ServeClient{TargetURL: "http://origin.invalid", LocalDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}}
	}
	first := startOriginPoolSession(t, newClient(firstServer, &firstDials))
	second := startOriginPoolSession(t, newClient(secondServer, &secondDials))
	for i := 0; i < 4; i++ {
		first.request(t, i%2 == 0)
		second.request(t, i%2 != 0)
	}
	if firstDials.Load() != 1 || secondDials.Load() != 1 || firstAccepted.Load() != 1 || secondAccepted.Load() != 1 {
		t.Fatalf("publishers shared or discarded configured dialers: dials %d/%d, sockets %d/%d", firstDials.Load(), secondDials.Load(), firstAccepted.Load(), secondAccepted.Load())
	}
}

type originPoolInjectedTransport struct {
	requests atomic.Int32
	closes   atomic.Int32
}

func (r *originPoolInjectedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.requests.Add(1)
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("origin response")), Request: req}, nil
}

func (r *originPoolInjectedTransport) CloseIdleConnections() { r.closes.Add(1) }

func TestOriginPoolInjectedTransportOwnership(t *testing.T) {
	transport := &originPoolInjectedTransport{}
	client := &ServeClient{TargetURL: "http://origin.invalid", HTTPTransport: transport, LocalDialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Error("injected transport unexpectedly dialed a socket")
		return nil, errors.New("unexpected dial")
	}}
	session := startOriginPoolSession(t, client)
	for i := 0; i < 4; i++ {
		session.request(t, i%2 == 0)
	}
	session.stop(t)
	if transport.requests.Load() != 4 || transport.closes.Load() != 0 {
		t.Fatalf("injected transport requests=%d, ownership closes=%d", transport.requests.Load(), transport.closes.Load())
	}
}

func TestOriginPoolTLSIsolation(t *testing.T) {
	server, accepted, _ := newOriginPoolServer(t, "https")
	trusted := startOriginPoolSession(t, &ServeClient{TargetURL: server.URL, SkipLocalTLSVerify: true})
	trusted.request(t, false)
	// The same origin in a different publisher must not inherit a socket that
	// bypassed certificate verification, or the first publisher's TLS policy.
	strict := &ServeClient{TargetURL: server.URL, LocalTLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	ctx, closePool := strict.withOriginPool(context.Background())
	defer closePool()
	for _, streaming := range []bool{false, true} {
		sender := &mockEstablishTunnelClient{}
		if streaming {
			strict.handleStreamingHTTPRequest(ctx, sender, &pb.ConnectionOpen{ConnectionId: "strict", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/"}}, http.NoBody)
			if accept := sender.getSentMsg(0).GetConnectionAccept(); accept == nil || accept.Success {
				t.Fatalf("strict publisher accepted an untrusted origin: %v", accept)
			}
		} else {
			strict.handleHTTPRequestContext(ctx, sender, &pb.HttpRequest{ConnectionId: "strict", Method: "GET", Path: "/"})
			if status := sender.getSentMsg(0).GetHttpResponse().GetStatusCode(); status != http.StatusBadGateway {
				t.Fatalf("strict publisher status=%d, want 502", status)
			}
		}
	}
	trusted.request(t, true)
	if got := accepted.Load(); got != 3 {
		t.Fatalf("TLS isolation accepted %d sockets, want 1 trusted and 2 rejected", got)
	}
}

type originPoolReconnectRelay struct {
	pb.UnimplementedTunnelServiceServer
	calls     atomic.Int32
	completed chan struct{}
}

func (r *originPoolReconnectRelay) EstablishTunnel(stream pb.TunnelService_EstablishTunnelServer) error {
	attempt := r.calls.Add(1)
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true}}}); err != nil {
		return err
	}
	if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: "relay-request", Method: "GET", Path: "/"}}}); err != nil {
		return err
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		if response := msg.GetHttpResponse(); response != nil {
			if response.StatusCode != 200 || string(response.Body) != "origin response" {
				return status.Error(codes.Internal, "unexpected origin response")
			}
			break
		}
	}
	if attempt == 1 {
		return status.Error(codes.Unavailable, "synthetic relay reconnect")
	}
	close(r.completed)
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestOriginPoolRunReconnectAndShutdown(t *testing.T) {
	origin, accepted, closed := newOriginPoolServer(t, "http")
	fixture := &originPoolReconnectRelay{completed: make(chan struct{})}
	grpcServer := grpc.NewServer()
	pb.RegisterTunnelServiceServer(grpcServer, fixture)
	relay := httptest.NewUnstartedServer(grpcServer)
	relay.EnableHTTP2 = true
	relay.StartTLS()
	t.Cleanup(relay.Close)
	t.Cleanup(grpcServer.Stop)
	ctx, cancel := context.WithCancel(context.Background())
	client := &ServeClient{TargetURL: origin.URL, ServerAddr: strings.TrimPrefix(relay.URL, "https://"),
		RelayTLSConfig: relay.Client().Transport.(*http.Transport).TLSClientConfig,
		Quiet:          true, Persistent: true, InitialDelay: time.Millisecond, MaxReconnectDelay: time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Run shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not stop after cancellation")
		}
	}
	t.Cleanup(stop)
	select {
	case <-fixture.completed:
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not serve through relay reconnect")
	}
	if fixture.calls.Load() != 2 || accepted.Load() != 1 {
		t.Fatalf("relay registrations=%d, origin sockets=%d, want 2/1", fixture.calls.Load(), accepted.Load())
	}
	stop()
	waitOriginPoolClosed(t, closed)
}
