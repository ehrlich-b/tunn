package host

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestProxyHTTPOverGRPCNegotiatesStreaming(t *testing.T) {
	stream := &mockWebProxyStream{}
	tunnel := &TunnelConnection{
		TunnelID:     "streaming",
		Stream:       stream,
		Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true},
	}
	proxy := &ProxyServer{}
	requestBody := strings.Repeat("request-data-", common.StreamChunkSize/4)
	request := httptest.NewRequest(http.MethodPost, "/mcp?session=one", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	requestMessages := make(chan []*pb.TunnelMessage, 1)
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			stream.mu.Lock()
			messages := append([]*pb.TunnelMessage(nil), stream.sentMsgs...)
			stream.mu.Unlock()

			var open *pb.ConnectionOpen
			halfClosed := false
			for _, message := range messages {
				if message.GetConnectionOpen() != nil {
					open = message.GetConnectionOpen()
				}
				if message.GetConnectionHalfClose() != nil {
					halfClosed = true
				}
			}
			if open != nil && halfClosed {
				requestMessages <- messages
				tunnel.routeConnectionMessage(&pb.TunnelMessage{
					Message: &pb.TunnelMessage_ConnectionAccept{
						ConnectionAccept: &pb.ConnectionAccept{
							ConnectionId: open.ConnectionId,
							Success:      true,
							HttpResponse: &pb.HttpResponseHead{
								StatusCode: http.StatusOK,
								Headers:    map[string]string{"Content-Type": "text/event-stream"},
							},
						},
					},
				})
				tunnel.routeConnectionMessage(&pb.TunnelMessage{
					Message: &pb.TunnelMessage_ConnectionData{
						ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte("event: one\n\n")},
					},
				})
				tunnel.routeConnectionMessage(&pb.TunnelMessage{
					Message: &pb.TunnelMessage_ConnectionData{
						ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte("event: two\n\n")},
					},
				})
				tunnel.routeConnectionMessage(&pb.TunnelMessage{
					Message: &pb.TunnelMessage_ConnectionHalfClose{
						ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId},
					},
				})
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	if err := proxy.proxyHTTPOverGRPC(recorder, request, tunnel); err != nil {
		t.Fatalf("proxyHTTPOverGRPC: %v", err)
	}
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("response = %d, %v", recorder.Code, recorder.Header())
	}
	if recorder.Body.String() != "event: one\n\nevent: two\n\n" {
		t.Fatalf("streamed body = %q", recorder.Body.String())
	}

	messages := <-requestMessages
	var open *pb.ConnectionOpen
	var body bytes.Buffer
	dataMessages := 0
	for _, message := range messages {
		if got := message.GetConnectionOpen(); got != nil {
			open = got
		}
		if got := message.GetConnectionData(); got != nil {
			dataMessages++
			body.Write(got.Data)
		}
		if message.GetHttpRequest() != nil {
			t.Fatal("negotiated stream used legacy buffered HttpRequest")
		}
	}
	if open == nil || open.HttpRequest.Path != "/mcp?session=one" {
		t.Fatalf("connection open = %#v", open)
	}
	if open.HttpRequest.ContentLength != int64(len(requestBody)) {
		t.Fatalf("content length = %d, want %d", open.HttpRequest.ContentLength, len(requestBody))
	}
	if open.HttpRequest.Headers["Content-Type"] != "application/json" {
		t.Fatalf("request headers = %#v", open.HttpRequest.Headers)
	}
	if dataMessages < 2 {
		t.Fatalf("request used %d data messages, want multiple chunks", dataMessages)
	}
	if body.String() != requestBody {
		t.Fatalf("streamed request body length = %d, want %d", body.Len(), len(requestBody))
	}
}

func TestLegacyClientKeepsBufferedHTTPPath(t *testing.T) {
	tunnel := &TunnelConnection{}
	if tunnel.Supports(common.CapabilityHTTPStreamV1) {
		t.Fatal("tunnel without advertised capability enabled streaming")
	}
}

func TestTunnelConnectionLimitRejectsPendingStream(t *testing.T) {
	tunnel := &TunnelConnection{pendingStreams: make(map[string]*pendingConnection)}
	for index := 0; index < common.MaxConcurrentConnections; index++ {
		tunnel.pendingStreams[fmt.Sprintf("connection-%d", index)] = newPendingConnection()
	}
	if _, err := tunnel.addPendingConnection("over-limit"); err == nil {
		t.Fatal("pending connection limit was not enforced")
	}
}
