package tunn

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func testHandlerOrigin(handler http.Handler) *handlerOrigin {
	return &handlerOrigin{handler: handler, incoming: make(chan net.Conn), done: make(chan struct{}), served: make(chan struct{})}
}

func TestSDKHandlerBufferedAndStreamingHTTP(t *testing.T) {
	result := make(chan string, 1)
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
		reg, err := registration(stream)
		if err != nil {
			return err
		}
		if err := acceptRegistration(stream, reg); err != nil {
			return err
		}
		if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: "buffered", Method: "POST", Path: "/buffered?q=one", Headers: map[string]string{"Host": "public.sdk.test", "X-Fixture": "header"}, Body: []byte("body")}}}); err != nil {
			return err
		}
		for {
			message, err := stream.Recv()
			if err != nil {
				return err
			}
			if response := message.GetHttpResponse(); response != nil {
				if response.StatusCode != http.StatusAccepted || string(response.Body) != "POST /buffered?q=one public.sdk.test header body" {
					result <- "buffered response fidelity failed"
					return errors.New("buffered response mismatch")
				}
				break
			}
		}
		if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: &pb.ConnectionOpen{ConnectionId: "stream", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "POST", Path: "/stream?q=two", ContentLength: 4, Headers: map[string]string{"Host": "public.sdk.test", "X-Fixture": "header"}}}}}); err != nil {
			return err
		}
		if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: "stream", Data: []byte("body")}}}); err != nil {
			return err
		}
		if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: "stream"}}}); err != nil {
			return err
		}
		var body strings.Builder
		accepted := false
		for {
			message, err := stream.Recv()
			if err != nil {
				return err
			}
			switch {
			case message.GetConnectionAccept() != nil:
				head := message.GetConnectionAccept()
				accepted = head.Success && head.HttpResponse.StatusCode == http.StatusAccepted
			case message.GetConnectionData() != nil:
				body.Write(message.GetConnectionData().Data)
			case message.GetConnectionHalfClose() != nil:
				if !accepted || body.String() != "POST /stream?q=two public.sdk.test header body" {
					result <- "streaming response fidelity failed"
				} else {
					result <- "ok"
				}
				return drainUntilCanceled(stream)
			}
		}
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, r.Method+" "+r.URL.RequestURI()+" "+r.Host+" "+r.Header.Get("X-Fixture")+" "+string(body))
	})
	o := fixtureOptions()
	o.Origin = "http://sdk-handler.invalid"
	o.TLSConfig = tlsConfig
	tunnel := startFixtureTunnel(t, context.Background(), o, dial, testHandlerOrigin(handler))
	select {
	case outcome := <-result:
		if outcome != "ok" {
			t.Fatal(outcome)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP forwarding did not finish")
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSDKCancellationStopsActiveHTTP(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			canceled := make(chan struct{})
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(canceled) })
			dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
				reg, err := registration(stream)
				if err != nil {
					return err
				}
				if err := acceptRegistration(stream, reg); err != nil {
					return err
				}
				var message *pb.TunnelMessage
				if mode == "buffered" {
					message = &pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: "active", Method: "GET", Path: "/"}}}
				} else {
					message = &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: &pb.ConnectionOpen{ConnectionId: "active", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/", ContentLength: 0}}}}
				}
				if err := stream.Send(message); err != nil {
					return err
				}
				return drainUntilCanceled(stream)
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			o := fixtureOptions()
			o.Origin = "http://sdk-handler.invalid"
			o.TLSConfig = tlsConfig
			tunnel := startFixtureTunnel(t, ctx, o, dial, testHandlerOrigin(handler))
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("request did not reach handler")
			}
			cancel()
			waitDone(t, tunnel)
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("handler did not receive cancellation")
			}
			if !errors.Is(tunnel.Wait(), context.Canceled) {
				t.Fatalf("cancellation result: %v", tunnel.Wait())
			}
		})
	}
}

func TestSDKCallerDeadline(t *testing.T) {
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
		reg, err := registration(stream)
		if err != nil {
			return err
		}
		if err := acceptRegistration(stream, reg); err != nil {
			return err
		}
		return drainUntilCanceled(stream)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	o := fixtureOptions()
	o.TLSConfig = tlsConfig
	tunnel := startFixtureTunnel(t, ctx, o, dial, nil)
	events := collectEvents(t, tunnel)
	if !errors.Is(tunnel.Wait(), context.DeadlineExceeded) || !errors.Is(events[len(events)-1].Err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline result: %v %v", tunnel.Wait(), events)
	}
}

func TestSDKInitializationFailureClosesHandlerTransport(t *testing.T) {
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
		if _, err := registration(stream); err != nil {
			return err
		}
		return stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{ErrorMessage: "rejected fixture"}}})
	})
	o := fixtureOptions()
	o.Origin = "http://sdk-handler.invalid"
	o.TLSConfig = tlsConfig
	origin := testHandlerOrigin(http.NotFoundHandler())
	tunnel := startFixtureTunnel(t, context.Background(), o, dial, origin)
	collectEvents(t, tunnel)
	select {
	case <-origin.done:
	default:
		t.Fatal("failed startup retained handler listener")
	}
	select {
	case <-origin.served:
	default:
		t.Fatal("failed startup retained handler server")
	}
	if connection, err := origin.dial(context.Background(), "tcp", "sdk-handler.invalid:80"); err == nil {
		_ = connection.Close()
		t.Fatal("failed publisher's handler transport still accepts requests")
	}
}

func TestSDKHandlerClosesHijackedPipes(t *testing.T) {
	hijacked := make(chan net.Conn, 1)
	origin := testHandlerOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, writer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = writer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n")
		_ = writer.Flush()
		hijacked <- connection
	}))
	origin.start(context.Background())
	defer origin.close()
	transport := &http.Transport{DialContext: origin.dial}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequest("GET", "http://sdk-handler.invalid/", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "fixture")
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("hijack status: %d", response.StatusCode)
	}
	var server net.Conn
	select {
	case server = <-hijacked:
	case <-time.After(time.Second):
		t.Fatal("handler did not hijack")
	}
	origin.close()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SDK-owned hijacked pipe was not closed: %v", err)
	}
	_ = server.Close()
}
