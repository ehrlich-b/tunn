package host

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// TunnelServer implements the gRPC TunnelService
type TunnelServer struct {
	pb.UnimplementedTunnelServiceServer

	mu           sync.RWMutex
	tunnels      map[string]*TunnelConnection
	wellKnownKey string // Free tier key that allows tunnel creation
}

// TunnelConnection represents an active tunnel connection
type TunnelConnection struct {
	TunnelID      string
	TargetURL     string
	Stream        pb.TunnelService_EstablishTunnelServer
	Connected     time.Time
	CreatorEmail  string
	AllowedEmails []string // Includes creator_email + any additional allowed emails
}

// NewTunnelServer creates a new gRPC tunnel server
func NewTunnelServer(wellKnownKey string) *TunnelServer {
	return &TunnelServer{
		tunnels:      make(map[string]*TunnelConnection),
		wellKnownKey: wellKnownKey,
	}
}

// EstablishTunnel implements the bidirectional streaming RPC for tunnel control
func (s *TunnelServer) EstablishTunnel(stream pb.TunnelService_EstablishTunnelServer) error {
	common.LogInfo("new tunnel stream established")

	// Wait for the initial RegisterClient message
	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive registration: %w", err)
	}

	regClient := msg.GetRegisterClient()
	if regClient == nil {
		return fmt.Errorf("expected RegisterClient message, got %T", msg.Message)
	}

	tunnelID := regClient.TunnelId
	targetURL := regClient.TargetUrl

	common.LogInfo("client registering", "tunnel_id", tunnelID, "target", targetURL)

	// Validate tunnel_key (authorization to create tunnels)
	if regClient.TunnelKey != s.wellKnownKey {
		common.LogError("invalid tunnel key", "tunnel_id", tunnelID, "provided_key", regClient.TunnelKey)
		respMsg := &pb.TunnelMessage{
			Message: &pb.TunnelMessage_RegisterResponse{
				RegisterResponse: &pb.RegisterResponse{
					Success:      false,
					ErrorMessage: "Invalid tunnel key. Use -key=WELL_KNOWN_KEY to create tunnels.",
				},
			},
		}
		stream.Send(respMsg)
		return fmt.Errorf("invalid tunnel key for tunnel %s", tunnelID)
	}

	// Validate and extract email from JWT
	creatorEmail := regClient.CreatorEmail
	if creatorEmail == "" {
		// Try to extract from JWT if not provided
		if regClient.AuthToken != "" {
			extractedEmail, err := common.ExtractEmailFromJWT(regClient.AuthToken)
			if err != nil {
				common.LogError("failed to extract email from JWT", "error", err)
				respMsg := &pb.TunnelMessage{
					Message: &pb.TunnelMessage_RegisterResponse{
						RegisterResponse: &pb.RegisterResponse{
							Success:      false,
							ErrorMessage: "Invalid JWT: cannot extract email",
						},
					},
				}
				stream.Send(respMsg)
				return fmt.Errorf("invalid JWT for tunnel %s: %w", tunnelID, err)
			}
			creatorEmail = extractedEmail
		} else {
			common.LogError("no creator email or JWT provided")
			respMsg := &pb.TunnelMessage{
				Message: &pb.TunnelMessage_RegisterResponse{
					RegisterResponse: &pb.RegisterResponse{
						Success:      false,
						ErrorMessage: "Authentication required. Run 'tunn login' first.",
					},
				},
			}
			stream.Send(respMsg)
			return fmt.Errorf("no authentication provided for tunnel %s", tunnelID)
		}
	}

	// Build complete allow-list (creator + allowed_emails)
	allowedEmails := make([]string, 0, len(regClient.AllowedEmails)+1)
	allowedEmails = append(allowedEmails, creatorEmail) // Creator always allowed
	for _, email := range regClient.AllowedEmails {
		if email != "" && email != creatorEmail {
			allowedEmails = append(allowedEmails, email)
		}
	}

	common.LogInfo("tunnel allow-list", "tunnel_id", tunnelID, "creator", creatorEmail, "allowed", allowedEmails)

	// Create tunnel connection
	conn := &TunnelConnection{
		TunnelID:      tunnelID,
		TargetURL:     targetURL,
		Stream:        stream,
		Connected:     time.Now(),
		CreatorEmail:  creatorEmail,
		AllowedEmails: allowedEmails,
	}

	// Register the tunnel
	s.mu.Lock()
	if _, exists := s.tunnels[tunnelID]; exists {
		s.mu.Unlock()
		// Send error response
		respMsg := &pb.TunnelMessage{
			Message: &pb.TunnelMessage_RegisterResponse{
				RegisterResponse: &pb.RegisterResponse{
					Success:      false,
					ErrorMessage: "tunnel ID already in use",
				},
			},
		}
		stream.Send(respMsg)
		return fmt.Errorf("tunnel ID %s already registered", tunnelID)
	}
	s.tunnels[tunnelID] = conn
	s.mu.Unlock()

	// Cleanup on disconnect
	defer func() {
		s.mu.Lock()
		delete(s.tunnels, tunnelID)
		s.mu.Unlock()
		common.LogInfo("tunnel disconnected", "tunnel_id", tunnelID)
	}()

	// Send success response
	publicURL := fmt.Sprintf("https://%s.tunn.to", tunnelID)
	respMsg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterResponse{
			RegisterResponse: &pb.RegisterResponse{
				Success:   true,
				PublicUrl: publicURL,
			},
		},
	}

	if err := stream.Send(respMsg); err != nil {
		return fmt.Errorf("failed to send registration response: %w", err)
	}

	common.LogInfo("tunnel registered", "tunnel_id", tunnelID, "url", publicURL)

	// Enter message processing loop
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			common.LogInfo("client closed stream", "tunnel_id", tunnelID)
			return nil
		}
		if err != nil {
			return fmt.Errorf("stream error: %w", err)
		}

		// Handle different message types
		switch m := msg.Message.(type) {
		case *pb.TunnelMessage_HealthCheck:
			// Respond to health check
			s.handleHealthCheck(stream, m.HealthCheck)

		case *pb.TunnelMessage_ProxyResponse:
			// Client acknowledging a proxy request
			common.LogInfo("proxy response received",
				"tunnel_id", tunnelID,
				"connection_id", m.ProxyResponse.ConnectionId,
				"success", m.ProxyResponse.Success)

		default:
			common.LogInfo("unexpected message type", "type", fmt.Sprintf("%T", m))
		}
	}
}

// handleHealthCheck responds to health check pings
func (s *TunnelServer) handleHealthCheck(stream pb.TunnelService_EstablishTunnelServer, hc *pb.HealthCheck) {
	response := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_HealthCheckResponse{
			HealthCheckResponse: &pb.HealthCheckResponse{
				Timestamp:         hc.Timestamp,
				ResponseTimestamp: time.Now().UnixMilli(),
			},
		},
	}

	if err := stream.Send(response); err != nil {
		common.LogInfo("failed to send health check response", "error", err)
	}
}

// GetTunnel retrieves a tunnel connection by ID
func (s *TunnelServer) GetTunnel(tunnelID string) (*TunnelConnection, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	conn, exists := s.tunnels[tunnelID]
	return conn, exists
}

// ListTunnels returns all active tunnels
func (s *TunnelServer) ListTunnels() []*TunnelConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tunnels := make([]*TunnelConnection, 0, len(s.tunnels))
	for _, conn := range s.tunnels {
		tunnels = append(tunnels, conn)
	}
	return tunnels
}

// GetActiveTunnelCount returns the number of active tunnels
func (s *TunnelServer) GetActiveTunnelCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tunnels)
}
