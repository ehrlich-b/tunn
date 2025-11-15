package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// ServeClient is the new gRPC-based tunnel client for "tunn serve"
type ServeClient struct {
	TunnelID   string
	TargetURL  string
	ServerAddr string
	AuthToken  string
	SkipVerify bool
}

// Run establishes a gRPC tunnel and handles control messages
func (s *ServeClient) Run(ctx context.Context) error {
	// Create TLS credentials
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.SkipVerify,
	}
	creds := credentials.NewTLS(tlsConfig)

	// Connect to the gRPC server
	common.LogInfo("connecting to proxy", "server", s.ServerAddr)
	conn, err := grpc.NewClient(s.ServerAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Create tunnel service client
	client := pb.NewTunnelServiceClient(conn)

	// Establish the bidirectional stream
	stream, err := client.EstablishTunnel(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish tunnel: %w", err)
	}

	common.LogInfo("gRPC stream established")

	// Send registration message
	regMsg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:  s.TunnelID,
				TargetUrl: s.TargetURL,
				AuthToken: s.AuthToken,
			},
		},
	}

	if err := stream.Send(regMsg); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	common.LogInfo("registration sent", "tunnel_id", s.TunnelID, "target", s.TargetURL)

	// Wait for registration response
	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive registration response: %w", err)
	}

	regResp := msg.GetRegisterResponse()
	if regResp == nil {
		return fmt.Errorf("expected RegisterResponse, got %T", msg.Message)
	}

	if !regResp.Success {
		return fmt.Errorf("registration failed: %s", regResp.ErrorMessage)
	}

	common.LogInfo("tunnel registered successfully", "public_url", regResp.PublicUrl)
	fmt.Printf("🔗 %s → %s\n", regResp.PublicUrl, s.TargetURL)

	// Start health check sender
	go s.sendHealthChecks(ctx, stream)

	// Enter message processing loop
	return s.processMessages(ctx, stream)
}

// processMessages handles incoming messages from the server
func (s *ServeClient) processMessages(ctx context.Context, stream pb.TunnelService_EstablishTunnelClient) error {
	for {
		select {
		case <-ctx.Done():
			common.LogInfo("context canceled, closing stream")
			return ctx.Err()
		default:
		}

		msg, err := stream.Recv()
		if err == io.EOF {
			common.LogInfo("server closed stream")
			return nil
		}
		if err != nil {
			return fmt.Errorf("stream receive error: %w", err)
		}

		switch m := msg.Message.(type) {
		case *pb.TunnelMessage_ProxyRequest:
			s.handleProxyRequest(stream, m.ProxyRequest)

		case *pb.TunnelMessage_HealthCheckResponse:
			// Calculate RTT
			rtt := time.Now().UnixMilli() - m.HealthCheckResponse.Timestamp
			common.LogDebug("health check response", "rtt_ms", rtt)

		default:
			common.LogInfo("unexpected message type", "type", fmt.Sprintf("%T", m))
		}
	}
}

// handleProxyRequest handles a proxy request from the server
func (s *ServeClient) handleProxyRequest(stream pb.TunnelService_EstablishTunnelClient, req *pb.ProxyRequest) {
	common.LogInfo("proxy request received",
		"connection_id", req.ConnectionId,
		"source", req.SourceAddress)

	// For now, just acknowledge the request
	// In Phase 3, this will actually establish a data connection to forward traffic
	resp := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_ProxyResponse{
			ProxyResponse: &pb.ProxyResponse{
				ConnectionId: req.ConnectionId,
				Success:      true,
			},
		},
	}

	if err := stream.Send(resp); err != nil {
		common.LogError("failed to send proxy response", "error", err)
	}
}

// sendHealthChecks periodically sends health check pings
func (s *ServeClient) sendHealthChecks(ctx context.Context, stream pb.TunnelService_EstablishTunnelClient) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			msg := &pb.TunnelMessage{
				Message: &pb.TunnelMessage_HealthCheck{
					HealthCheck: &pb.HealthCheck{
						Timestamp: time.Now().UnixMilli(),
					},
				},
			}

			if err := stream.Send(msg); err != nil {
				common.LogError("failed to send health check", "error", err)
				return
			}

			common.LogDebug("health check sent")
		}
	}
}
