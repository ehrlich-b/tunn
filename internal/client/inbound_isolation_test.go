package client

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type isolationStream struct {
	ctx      context.Context
	incoming chan *pb.TunnelMessage
	outgoing chan *pb.TunnelMessage
}

func (s *isolationStream) Recv() (*pb.TunnelMessage, error) {
	select {
	case msg := <-s.incoming:
		return msg, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *isolationStream) Send(msg *pb.TunnelMessage) error {
	select {
	case s.outgoing <- msg:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

type isolationLog struct {
	heartbeat chan struct{}
	once      sync.Once
}

func (l *isolationLog) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("health check response")) {
		l.once.Do(func() { close(l.heartbeat) })
	}
	return len(p), nil
}

// The stalled adapters never consume the upload. Every message, including the
// cancel and heartbeat, goes through the production shared receive loop.
type isolationConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *isolationConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestInboundIsolation(t *testing.T)           { testInboundIsolation(t, 40, true) }
func TestInboundIsolationBelowLimit(t *testing.T) { testInboundIsolation(t, 1, false) }

func testInboundIsolation(t *testing.T, chunks int, overflow bool) {
	for _, protocol := range []string{"http", "tcp", "websocket"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &isolationStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 128), outgoing: make(chan *pb.TunnelMessage, 128)}
			log := &isolationLog{heartbeat: make(chan struct{})}
			client := &ServeClient{TargetURL: "http://origin.invalid", Logger: slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: slog.LevelDebug}))}
			stalled, victimReady, victimCanceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
			stalledCanceled := make(chan struct{})
			client.HTTPTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/slow":
					close(stalled)
					<-r.Context().Done()
					close(stalledCanceled)
					return nil, r.Context().Err()
				case "/cancel":
					close(victimReady)
					<-r.Context().Done()
					close(victimCanceled)
					return nil, r.Context().Err()
				default:
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("healthy")), Request: r}, nil
				}
			})
			var peers sync.WaitGroup
			dialCount := 0 // DialContext calls are sequenced by ready signals below.
			client.DialContext = func(context.Context, string, string) (net.Conn, error) {
				local, peer := net.Pipe()
				dialCount++
				index := dialCount
				peers.Add(1)
				go func() {
					defer peers.Done()
					defer peer.Close()
					switch index {
					case 1:
						close(stalled)
						<-ctx.Done()
					case 2:
						close(victimReady)
						_, _ = io.Copy(io.Discard, peer)
						close(victimCanceled)
					default:
						// A complete fixed-size upload suffices; net.Pipe has no CloseWrite.
						body := make([]byte, len("request"))
						_, err := io.ReadFull(peer, body)
						if err == nil && string(body) == "request" {
							_, _ = peer.Write([]byte("healthy"))
						}
					}
				}()
				if index == 1 {
					return &isolationConn{Conn: local, closed: stalledCanceled}, nil
				}
				return local, nil
			}
			if protocol == "tcp" {
				client.EndpointProtocol = "tcp"
				client.TargetURL = "origin.invalid:1"
			}
			if protocol == "websocket" {
				client.LocalDialContext = func(context.Context, string, string) (net.Conn, error) {
					local, peer := net.Pipe()
					peers.Add(1)
					go func() {
						defer peers.Done()
						defer peer.Close()
						request, err := http.ReadRequest(bufio.NewReader(peer))
						if err != nil {
							return
						}
						// RFC 6455 example key/accept, used in the open below.
						_, err = fmt.Fprint(peer, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
						_ = request.Body.Close()
						if err == nil {
							close(stalled)
							<-ctx.Done()
						}
					}()
					return &isolationConn{Conn: local, closed: stalledCanceled}, nil
				}
			}
			done := make(chan error, 1)
			go func() { done <- client.ServeMessages(ctx, stream) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("receiver failed to join after cancellation")
				}
				peers.Wait()
			}()
			open := func(id, proto, path string) {
				method := "POST"
				if proto == "websocket" {
					method = "GET"
				}
				stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: &pb.ConnectionOpen{ConnectionId: id, Protocol: proto, HttpRequest: &pb.HttpRequestHead{Method: method, Path: path, Headers: map[string]string{"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}}}}}
			}
			wait := func(ch <-chan struct{}, what string) {
				t.Helper()
				select {
				case <-ch:
				case <-time.After(time.Second):
					t.Errorf("blocked %s stream delayed %s", protocol, what)
				}
			}
			open("slow", protocol, "/slow")
			wait(stalled, "origin readiness")
			otherProtocol := "http"
			if protocol == "tcp" {
				otherProtocol = "tcp"
			}
			open("victim", otherProtocol, "/cancel")
			wait(victimReady, "cancel target readiness")
			chunk := bytes.Repeat([]byte("x"), common.StreamChunkSize)
			if protocol == "websocket" {
				// One valid masked binary frame, whose payload write blocks at the origin.
				chunk[0], chunk[1] = 0x82, 0xfe
				for i := 4; i < 8; i++ {
					chunk[i] = 0
				}
				chunk[2], chunk[3] = 0x7f, 0xf8 // 32760-byte payload
			}
			for i := 0; i < chunks; i++ {
				stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: "slow", Data: chunk}}}
			}
			// EOF on a saturated queue must also never block the receiver.
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: "slow"}}}
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{ConnectionClose: &pb.ConnectionClose{ConnectionId: "victim"}}}
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_HealthCheckResponse{HealthCheckResponse: &pb.HealthCheckResponse{Timestamp: time.Now().UnixMilli()}}}
			open("healthy", otherProtocol, "/healthy")
			if protocol == "tcp" {
				stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: "healthy", Data: []byte("request")}}}
			}
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: "healthy"}}}
			wait(log.heartbeat, "heartbeat")
			wait(victimCanceled, "remote cancellation")
			if overflow {
				wait(stalledCanceled, "overflow cleanup")
			}
			var response strings.Builder
			overflowClosed := false
			healthyClosed := false
			deadline := time.NewTimer(time.Second)
			defer deadline.Stop()
			for {
				select {
				case msg := <-stream.outgoing:
					if end := msg.GetConnectionClose(); end != nil && end.ConnectionId == "slow" {
						if strings.Contains(end.ErrorMessage, "queue overflow") {
							overflowClosed = true
						}
						if !overflow {
							t.Error("below-limit stalled stream was closed")
						}
					}
					if data := msg.GetConnectionData(); data != nil && data.ConnectionId == "healthy" {
						response.Write(data.Data)
					}
					if end := msg.GetConnectionHalfClose(); end != nil && end.ConnectionId == "healthy" {
						if response.String() != "healthy" {
							t.Errorf("healthy response = %q", response.String())
						}
						healthyClosed = true
					}
				case <-deadline.C:
					t.Errorf("completion missing: healthy=%v overflow=%v", healthyClosed, overflowClosed)
					return
				}
				if healthyClosed && (!overflow || overflowClosed) {
					if !overflow {
						select {
						case <-stalledCanceled:
							t.Error("below-limit stalled stream canceled")
						default:
						}
					}
					return
				}
			}
		})
	}
}

func TestInboundQueuedEOFAndBufferOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := newInboundConnectionManagerWithLimit(1)
	defer func() { manager.closeAll(io.EOF); manager.workers.Wait() }()
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	received := make(chan []byte, 1)
	client := &ServeClient{TargetURL: "http://origin.invalid", HTTPTransport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		first := make([]byte, 1)
		_, err := io.ReadFull(r.Body, first)
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		rest, readErr := io.ReadAll(r.Body)
		if err != nil || readErr != nil {
			return nil, fmt.Errorf("upload: %v %v", err, readErr)
		}
		received <- append(first, rest...)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})}
	sender := &isolationStream{ctx: ctx, outgoing: make(chan *pb.TunnelMessage, 16)}
	manager.open(ctx, client, sender, &pb.ConnectionOpen{ConnectionId: "ordered", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "POST", Path: "/"}})
	manager.write("ordered", []byte("prefix"))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upload did not start")
	}
	manager.write("ordered", nil) // Empty data must not mean EOF.
	expected := []byte("prefix")
	for i := 0; i < 16; i++ {
		data := bytes.Repeat([]byte{byte(i)}, common.StreamChunkSize)
		expected = append(expected, data...)
		manager.write("ordered", data)
		data[0] = 255 // The queued bytes belong to the stream after write returns.
	}
	manager.halfClose("ordered") // EOF must work even with all 16 slots occupied.
	manager.halfClose("ordered")
	manager.write("ordered", []byte("after EOF"))
	// Release without closing twice in cleanup.
	release <- struct{}{}
	select {
	case actual := <-received:
		if !bytes.Equal(actual, expected) {
			t.Fatalf("upload changed or lost queued data: got %d bytes, want %d", len(actual), len(expected))
		}
	case <-time.After(time.Second):
		t.Fatal("queued EOF did not drain the upload")
	}
}

func TestInboundOversizedChunkReleasesSlot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := newInboundConnectionManagerWithLimit(1)
	defer func() { manager.closeAll(io.EOF); manager.workers.Wait() }()
	ready, canceled := make(chan struct{}), make(chan struct{})
	client := &ServeClient{TargetURL: "http://origin.invalid", HTTPTransport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(ready)
		<-r.Context().Done()
		close(canceled)
		return nil, r.Context().Err()
	})}
	sender := &isolationStream{ctx: ctx, outgoing: make(chan *pb.TunnelMessage, 16)}
	manager.open(ctx, client, sender, &pb.ConnectionOpen{ConnectionId: "oversized", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "POST", Path: "/"}})
	<-ready
	manager.write("oversized", make([]byte, common.StreamChunkSize+1))
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("oversized stream not canceled")
	}
	manager.workers.Wait()
	if manager.get("oversized") != nil || len(manager.slots) != 0 {
		t.Fatal("oversized stream retained its slot")
	}
	for len(sender.outgoing) > 0 {
		msg := <-sender.outgoing
		if end := msg.GetConnectionClose(); end != nil && strings.Contains(end.ErrorMessage, "oversized") {
			return
		}
	}
	t.Fatal("oversized stream close not sent")
}

func TestInboundConcurrentInputClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := newInboundConnectionManager()
	defer func() { manager.closeAll(io.EOF); manager.workers.Wait() }()
	client := &ServeClient{TargetURL: "http://origin.invalid", HTTPTransport: roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })}
	sender := &isolationStream{ctx: ctx, outgoing: make(chan *pb.TunnelMessage, 16)}
	manager.open(ctx, client, sender, &pb.ConnectionOpen{ConnectionId: "race", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "POST", Path: "/"}})
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			manager.write("race", []byte("body"))
			manager.halfClose("race")
			manager.close("race", "")
		}()
	}
	workers.Wait()
	if len(manager.slots) != 0 {
		t.Fatal("closed stream retained its slot")
	}
}
