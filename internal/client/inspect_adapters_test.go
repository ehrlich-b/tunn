package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type inspectContractSender struct {
	fail        bool
	onHalfClose func()
}

func (s inspectContractSender) Send(msg *pb.TunnelMessage) error {
	if s.fail && msg.GetConnectionData() != nil {
		return errors.New("fixture relay send failure")
	}
	if s.onHalfClose != nil && msg.GetConnectionHalfClose() != nil {
		s.onHalfClose()
	}
	return nil
}
func TestInspectContractStreamingTerminalOutcomes(t *testing.T) {
	for _, mode := range []string{"http", "http-known-length", "sse", "response_error", "relay_error", "cancel", "cancel_after_half_close"} {
		t.Run(mode, func(t *testing.T) {
			client := &ServeClient{TargetURL: "http://fixture.test", HTTPTimeout: time.Second}
			client.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				local, peer := net.Pipe()
				go func() {
					defer func() { _ = peer.Close() }()
					r, err := http.ReadRequest(bufio.NewReader(peer))
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, r.Body)
					_ = r.Body.Close()
					typeValue := "text/plain"
					if mode == "sse" {
						typeValue = "text/event-stream"
					}
					length := 2
					if mode == "response_error" {
						length = 3
					}
					_, _ = fmt.Fprintf(peer, "HTTP/1.1 202 Accepted\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\nok", typeValue, length)
				}()
				return local, nil
			}
			client.Inspector = NewInspectorWithBodyCapture(client, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			length := int64(-1)
			if mode == "http-known-length" {
				length = 4
			}
			sender := inspectContractSender{fail: mode == "relay_error"}
			if mode == "cancel_after_half_close" {
				sender.onHalfClose = cancel
			}
			client.handleStreamingHTTPRequest(ctx, sender, &pb.ConnectionOpen{ConnectionId: "correlation-7", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "POST", Path: "/hook", ContentLength: length}}, strings.NewReader("body"))
			events := client.Inspector.list()
			if len(events) != 1 {
				t.Fatal(events)
			}
			e := events[0]
			want := "complete"
			if mode == "response_error" {
				want = "response_error"
			}
			if mode == "relay_error" {
				want = "relay_error"
			}
			if mode == "cancel" {
				want = "canceled"
			}
			if e.TerminalReason != want || e.ConnectionID != "correlation-7" || client.Inspector.snapshot().ActiveStreams != 0 {
				t.Fatalf("event=%+v", e)
			}
			if mode != "cancel" && (e.Status != 202 || e.RequestBytes != 4 || e.ResponseBytes != 2) {
				t.Fatalf("observed bytes/status=%+v", e)
			}
			if (mode == "http" || mode == "http-known-length") && !e.BodyComplete {
				t.Fatalf("complete request was not replayable: %+v", e)
			}
			if mode == "sse" && (e.Protocol != "sse" || len(e.Body) > 0 || e.Reconstructable) {
				t.Fatalf("SSE retained/replayed content: %+v", e)
			}
		})
	}
}
func TestInspectContractPublisherDeniedAdmissions(t *testing.T) {
	client := &ServeClient{TargetURL: "http://fixture.test", RequireUpstreamAuth: true}
	client.Inspector = NewInspector(client)
	manager := newInboundConnectionManagerWithLimit(1)
	manager.open(context.Background(), client, inspectContractSender{}, nil)
	manager.slots <- struct{}{}
	manager.open(context.Background(), client, inspectContractSender{}, &pb.ConnectionOpen{ConnectionId: "quota", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/"}})
	<-manager.slots
	client.handleStreamingHTTPRequest(context.Background(), inspectContractSender{}, &pb.ConnectionOpen{ConnectionId: "auth", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/"}}, strings.NewReader(""))
	if client.Inspector.snapshot().DeniedAdmissions != 3 || len(manager.connections) != 0 || len(manager.slots) != 0 {
		t.Fatalf("metrics=%+v", client.Inspector.snapshot())
	}
	e := client.Inspector.list()[0]
	if e.Status != 401 || e.TerminalReason != "auth_required" {
		t.Fatalf("auth outcome=%+v", e)
	}
}
func TestInspectContractWebSocketMetadataOnly(t *testing.T) {
	client := &ServeClient{TargetURL: "http://fixture.test", DialContext: inspectContractTarget(nil, 401, nil, false)}
	client.Inspector = NewInspectorWithBodyCapture(client, true)
	client.handleWebSocket(context.Background(), inspectContractSender{}, &pb.ConnectionOpen{ConnectionId: "ws-rejection", Protocol: "websocket", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/ws?token=QUERY_SENTINEL", Headers: map[string]string{"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Authorization": "Bearer HEADER_SENTINEL"}}}, strings.NewReader(""))
	e := client.Inspector.list()[0]
	if e.Protocol != "websocket" || e.Status != 401 || e.ResponseBytes != 2 || e.Reconstructable || e.BodyCaptured || len(e.Body) > 0 || e.TerminalReason != "complete" {
		t.Fatalf("WS outcome=%+v", e)
	}
	if webSocketTerminalReason(common.ErrWebSocketMessageTooLarge) != "message_limit" || webSocketTerminalReason(common.ErrWebSocketProtocol) != "protocol_error" {
		t.Fatal("WebSocket terminal reasons lost")
	}
}
func TestInspectContractTCPMetadataOnly(t *testing.T) {
	client := &ServeClient{TargetURL: "fixture-tcp:8080"}
	client.DialContext = func(context.Context, string, string) (net.Conn, error) {
		local, peer := net.Pipe()
		go func() {
			defer func() { _ = peer.Close() }()
			buffer := make([]byte, 3)
			if _, err := io.ReadFull(peer, buffer); err != nil {
				return
			}
			_, _ = peer.Write([]byte("pong"))
		}()
		return local, nil
	}
	client.Inspector = NewInspectorWithBodyCapture(client, true)
	client.handleStreamingTCP(context.Background(), inspectContractSender{}, "tcp-correlation", strings.NewReader("raw"))
	e := client.Inspector.list()[0]
	if e.Protocol != "tcp" || e.Status != 200 || e.RequestBytes != 3 || e.ResponseBytes != 4 || e.ConnectionID != "tcp-correlation" || e.BodyCaptured || e.Reconstructable || len(e.Body) > 0 || e.TerminalReason != "peer_closed" {
		t.Fatalf("TCP outcome=%+v", e)
	}
}

func TestInspectContractBufferedFailureLogsRedacted(t *testing.T) {
	var log bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	client := &ServeClient{TargetURL: "://bad-target"}
	client.Inspector = NewInspector(client)
	client.handleHttpRequest(inspectContractSender{}, &pb.HttpRequest{ConnectionId: "correlation-safe", Method: "POST", Path: "/?token=QUERY_SENTINEL", Headers: map[string]string{"Authorization": "Bearer HEADER_SENTINEL"}, Body: []byte("BODY_SENTINEL")})
	if strings.Contains(log.String(), "SENTINEL") || !strings.Contains(log.String(), "correlation-safe") {
		t.Fatalf("unsafe error log: %s", log.String())
	}
	if client.Inspector.list()[0].TerminalReason != "target_error" {
		t.Fatal("missing buffered failure outcome")
	}
}

func TestInspectContractBufferedOriginalAndReplayMatch(t *testing.T) {
	deliveries := make(chan inspectContractDelivery, 2)
	client := &ServeClient{TargetURL: "http://original.test:8080", RequireUpstreamAuth: true, DialContext: inspectContractTarget(deliveries, 202, nil, false)}
	client.Inspector = NewInspectorWithBodyCapture(client, true)
	headers := map[string]string{"Authorization": "Bearer HEADER_SENTINEL", "Cookie": "session=COOKIE_SENTINEL", "Host": "application.test", "Content-Type": "text/plain"}
	client.handleHttpRequest(inspectContractSender{}, &pb.HttpRequest{ConnectionId: "buffered-correlation", Method: "POST", Path: "/hook", Headers: headers, Body: []byte("fixture body")})
	events := client.Inspector.list()
	if len(events) != 1 || events[0].Status != 202 || !events[0].BodyComplete || events[0].Headers["Authorization"] != redacted {
		t.Fatalf("buffered capture: %+v", events)
	}
	client.TargetURL = "http://changed.test:9090"
	result, err := client.Inspector.replay(context.Background(), events[0].ID, inspectionReplayInput{Action: inspectContractAction(t, client.Inspector, events[0].ID), Headers: headers})
	if err != nil || result.Status != 202 || result.ResponseBytes != 2 {
		t.Fatalf("replay=%+v err=%v", result, err)
	}
	original, replayed := <-deliveries, <-deliveries
	if original != replayed || original.address != "original.test:8080" || original.host != "application.test" {
		t.Fatalf("original=%+v replay=%+v", original, replayed)
	}
}
