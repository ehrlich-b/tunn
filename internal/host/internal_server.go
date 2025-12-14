package host

import (
	"context"
	"fmt"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// InternalServer implements the gRPC InternalService
type InternalServer struct {
	internalv1.UnimplementedInternalServiceServer
	tunnelServer *TunnelServer
	publicAddr   string
}

// NewInternalServer creates a new gRPC internal server
func NewInternalServer(tunnelServer *TunnelServer, publicAddr string) *InternalServer {
	return &InternalServer{
		tunnelServer: tunnelServer,
		publicAddr:   publicAddr,
	}
}

// FindTunnel implements the RPC for finding a tunnel on another node
func (s *InternalServer) FindTunnel(ctx context.Context, req *internalv1.FindTunnelRequest) (*internalv1.FindTunnelResponse, error) {
	tunnelID := req.GetTunnelId()
	common.LogInfo("internal request to find tunnel", "tunnel_id", tunnelID)

	if _, exists := s.tunnelServer.GetTunnel(tunnelID); exists {
		common.LogInfo("tunnel found locally", "tunnel_id", tunnelID)
		return &internalv1.FindTunnelResponse{
			Found:       true,
			NodeAddress: s.publicAddr,
		}, nil
	}

	common.LogInfo("tunnel not found locally", "tunnel_id", tunnelID)
	return &internalv1.FindTunnelResponse{
		Found: false,
	}, nil
}

// ForwardUdpPacket implements the RPC for forwarding a UDP packet to a tunnel on this node
func (s *InternalServer) ForwardUdpPacket(ctx context.Context, req *internalv1.ForwardUdpPacketRequest) (*internalv1.ForwardUdpPacketResponse, error) {
	tunnelID := req.GetTunnelId()
	sourceAddr := req.GetSourceAddress()
	data := req.GetData()

	common.LogDebug("internal request to forward UDP packet",
		"tunnel_id", tunnelID,
		"source", sourceAddr,
		"bytes", len(data))

	// Find the tunnel connection
	conn, exists := s.tunnelServer.GetTunnel(tunnelID)
	if !exists {
		return &internalv1.ForwardUdpPacketResponse{
			Success:      false,
			ErrorMessage: "tunnel not found on this node",
		}, nil
	}

	// Create response channel
	respChan := make(chan []byte, 1)
	connID := fmt.Sprintf("udp-%s-%d", sourceAddr, time.Now().UnixNano())

	// Register response handler
	conn.mu.Lock()
	if conn.udpResponses == nil {
		conn.udpResponses = make(map[string]chan []byte)
	}
	conn.udpResponses[connID] = respChan
	conn.mu.Unlock()

	// Clean up response channel when done
	defer func() {
		conn.mu.Lock()
		delete(conn.udpResponses, connID)
		conn.mu.Unlock()
		close(respChan)
	}()

	// Send UDP packet to the tunnel
	udpPacket := &pb.UdpPacket{
		TunnelId:           tunnelID,
		SourceAddress:      sourceAddr,
		DestinationAddress: "",
		Data:               data,
		FromClient:         false,
		TimestampMs:        time.Now().UnixMilli(),
	}

	err := conn.Stream.Send(&pb.TunnelMessage{
		Message: &pb.TunnelMessage_UdpPacket{
			UdpPacket: udpPacket,
		},
	})
	if err != nil {
		common.LogError("failed to send UDP packet to tunnel", "tunnel_id", tunnelID, "error", err)
		return &internalv1.ForwardUdpPacketResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to send packet: %v", err),
		}, nil
	}

	// Wait for response with timeout
	select {
	case responseData := <-respChan:
		return &internalv1.ForwardUdpPacketResponse{
			Success:      true,
			ResponseData: responseData,
		}, nil
	case <-time.After(5 * time.Second):
		// Timeout - no response from server
		return &internalv1.ForwardUdpPacketResponse{
			Success:      true,
			ResponseData: []byte{}, // Empty response is OK for UDP
		}, nil
	case <-ctx.Done():
		return &internalv1.ForwardUdpPacketResponse{
			Success:      false,
			ErrorMessage: "context cancelled",
		}, nil
	}
}
