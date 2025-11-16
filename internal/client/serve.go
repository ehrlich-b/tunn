package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// ServeClient is the new gRPC-based tunnel client for "tunn serve"
type ServeClient struct {
	TunnelID      string
	TargetURL     string
	ServerAddr    string
	AuthToken     string
	TunnelKey     string
	AllowedEmails []string
	SkipVerify    bool
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

	// Extract email from JWT
	creatorEmail, err := common.ExtractEmailFromJWT(s.AuthToken)
	if err != nil {
		return fmt.Errorf("failed to extract email from JWT: %w", err)
	}

	common.LogInfo("extracted creator email", "email", creatorEmail)

	// Send registration message
	regMsg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:      s.TunnelID,
				TargetUrl:     s.TargetURL,
				AuthToken:     s.AuthToken,
				CreatorEmail:  creatorEmail,
				AllowedEmails: s.AllowedEmails,
				TunnelKey:     s.TunnelKey,
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
		case *pb.TunnelMessage_HttpRequest:
			// Handle HTTP request from proxy - make request to local target and send response
			go s.handleHttpRequest(stream, m.HttpRequest)

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

// handleHttpRequest handles an HTTP request from the proxy, makes a request to the local target, and sends back the response
func (s *ServeClient) handleHttpRequest(stream pb.TunnelService_EstablishTunnelClient, httpReq *pb.HttpRequest) {
	common.LogInfo("http request received",
		"connection_id", httpReq.ConnectionId,
		"method", httpReq.Method,
		"path", httpReq.Path)

	// Build the target URL
	targetURL := s.TargetURL + httpReq.Path

	// Create HTTP request
	req, err := http.NewRequest(httpReq.Method, targetURL, bytes.NewReader(httpReq.Body))
	if err != nil {
		common.LogError("failed to create http request", "error", err)
		s.sendErrorResponse(stream, httpReq.ConnectionId, http.StatusBadGateway, "Failed to create request")
		return
	}

	// Copy headers
	for key, value := range httpReq.Headers {
		req.Header.Set(key, value)
	}

	// Make the request to local target
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		common.LogError("failed to make http request to target", "error", err, "target", targetURL)
		s.sendErrorResponse(stream, httpReq.ConnectionId, http.StatusBadGateway, "Failed to reach local target")
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		common.LogError("failed to read response body", "error", err)
		s.sendErrorResponse(stream, httpReq.ConnectionId, http.StatusBadGateway, "Failed to read response")
		return
	}

	// Convert headers to map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = values[0]
	}

	// Send HttpResponse back
	httpResp := &pb.HttpResponse{
		ConnectionId: httpReq.ConnectionId,
		StatusCode:   int32(resp.StatusCode),
		Headers:      headers,
		Body:         body,
	}

	msg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_HttpResponse{
			HttpResponse: httpResp,
		},
	}

	if err := stream.Send(msg); err != nil {
		common.LogError("failed to send http response", "error", err)
		return
	}

	common.LogInfo("http response sent",
		"connection_id", httpReq.ConnectionId,
		"status", resp.StatusCode,
		"body_size", len(body))
}

// sendErrorResponse sends an error response back to the proxy
func (s *ServeClient) sendErrorResponse(stream pb.TunnelService_EstablishTunnelClient, connectionID string, statusCode int, message string) {
	httpResp := &pb.HttpResponse{
		ConnectionId: connectionID,
		StatusCode:   int32(statusCode),
		Headers: map[string]string{
			"Content-Type": "text/plain",
		},
		Body: []byte(message),
	}

	msg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_HttpResponse{
			HttpResponse: httpResp,
		},
	}

	if err := stream.Send(msg); err != nil {
		common.LogError("failed to send error response", "error", err)
	}
}

// handleProxyRequest handles a proxy request from the server
func (s *ServeClient) handleProxyRequest(stream pb.TunnelService_EstablishTunnelClient, req *pb.ProxyRequest) {
	common.LogInfo("proxy request received",
		"connection_id", req.ConnectionId,
		"source", req.SourceAddress)

	// For now, just acknowledge the request
	// This legacy handler is for the old ProxyRequest message type
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
