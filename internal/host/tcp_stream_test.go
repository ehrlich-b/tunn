package host

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestProxyTCPOverGRPC(t *testing.T) {
	stream := &mockWebProxyStream{}
	tunnel := &TunnelConnection{
		TunnelID:         "database",
		Stream:           stream,
		EndpointProtocol: "tcp",
		Capabilities:     map[string]bool{common.CapabilityConnectionStreamV1: true},
	}
	proxy := &ProxyServer{}
	request := httptest.NewRequest(http.MethodConnect, common.TCPConnectPath, bytes.NewReader([]byte("client-bytes")))
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
						ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true},
					},
				})
				tunnel.routeConnectionMessage(&pb.TunnelMessage{
					Message: &pb.TunnelMessage_ConnectionData{
						ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte("server-bytes")},
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

	if err := proxy.proxyTCPOverGRPC(recorder, request, tunnel); err != nil {
		t.Fatalf("proxyTCPOverGRPC: %v", err)
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "server-bytes" {
		t.Fatalf("TCP response = %d %q", recorder.Code, recorder.Body.String())
	}

	messages := <-requestMessages
	var requestBody bytes.Buffer
	for _, message := range messages {
		if open := message.GetConnectionOpen(); open != nil && open.Protocol != "tcp" {
			t.Fatalf("connection protocol = %q", open.Protocol)
		}
		if data := message.GetConnectionData(); data != nil {
			requestBody.Write(data.Data)
		}
	}
	if requestBody.String() != "client-bytes" {
		t.Fatalf("TCP request = %q", requestBody.String())
	}
}
