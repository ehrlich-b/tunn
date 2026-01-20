package host

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/time/rate"
)

// reservedSubdomains are blocked to prevent phishing and squatting
var reservedSubdomains = map[string]bool{
	// Infrastructure
	"www": true, "api": true, "app": true, "admin": true, "auth": true,
	"login": true, "static": true, "cdn": true, "assets": true, "images": true,
	"mail": true, "smtp": true, "pop": true, "imap": true, "mx": true,
	"ns": true, "ns1": true, "ns2": true, "dns": true,
	"ftp": true, "sftp": true, "ssh": true, "vpn": true,
	"dev": true, "staging": true, "prod": true, "test": true, "beta": true,
	"status": true, "health": true, "metrics": true, "monitor": true,

	// Common phishing targets
	"google": true, "gmail": true, "youtube": true,
	"facebook": true, "instagram": true, "whatsapp": true, "meta": true,
	"apple": true, "icloud": true, "itunes": true,
	"microsoft": true, "outlook": true, "office": true, "azure": true,
	"amazon": true, "aws": true, "prime": true,
	"paypal": true, "venmo": true, "cashapp": true, "stripe": true,
	"chase": true, "bankofamerica": true, "wellsfargo": true, "citi": true,
	"netflix": true, "spotify": true, "hulu": true, "disney": true,
	"twitter": true, "x": true, "linkedin": true, "tiktok": true,
	"github": true, "gitlab": true, "bitbucket": true,
	"slack": true, "zoom": true, "teams": true, "discord": true,
	"dropbox": true, "box": true, "drive": true,

	// Security-sensitive
	"secure": true, "security": true, "account": true, "accounts": true,
	"billing": true, "payment": true, "pay": true, "checkout": true,
	"verify": true, "verification": true, "confirm": true, "reset": true,
	"password": true, "signin": true, "signup": true, "register": true,
	"support": true, "help": true, "helpdesk": true,
}

// isReservedSubdomain checks if a tunnel ID is reserved
func isReservedSubdomain(tunnelID string) bool {
	return reservedSubdomains[strings.ToLower(tunnelID)]
}

// isValidDNSLabel checks if a tunnel ID is a valid DNS label per RFC 1123.
// Must be 1-63 chars, contain only lowercase letters, digits, hyphens,
// and start/end with alphanumeric.
func isValidDNSLabel(tunnelID string) bool {
	if len(tunnelID) == 0 || len(tunnelID) > 63 {
		return false
	}

	// Must start with alphanumeric
	first := tunnelID[0]
	if !((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')) {
		return false
	}

	// Must end with alphanumeric
	last := tunnelID[len(tunnelID)-1]
	if !((last >= 'a' && last <= 'z') || (last >= '0' && last <= '9')) {
		return false
	}

	// Middle chars can be alphanumeric or hyphen
	for i := 1; i < len(tunnelID)-1; i++ {
		c := tunnelID[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}

	return true
}

// TunnelServer implements the gRPC TunnelService
type TunnelServer struct {
	pb.UnimplementedTunnelServiceServer

	mu         sync.RWMutex
	tunnels    map[string]*TunnelConnection
	cfg        *config.Config
	userTokens map[string]string   // email -> token from users.yaml
	accounts   *store.AccountStore // Account storage for subdomain reservations
	storage    storage.Storage     // Unified storage for tunnel registration/limits
}

// Bandwidth limits are defined in limits.go

// TunnelConnection represents an active tunnel connection
type TunnelConnection struct {
	TunnelID      string
	TargetURL     string
	Stream        pb.TunnelService_EstablishTunnelServer
	Connected     time.Time
	CreatorEmail  string
	AccountID     string   // Account ID for usage tracking (from storage)
	AllowedEmails []string // Includes creator_email + any additional allowed emails
	Plan          string   // "free" or "pro" - cached for quota checks

	// Bandwidth rate limiter (token bucket)
	rateLimiter *rate.Limiter

	// Stream send mutex - gRPC streams are NOT thread-safe for concurrent Send()
	streamMu sync.Mutex

	// HTTP request tracking
	pendingMu       sync.RWMutex
	pendingRequests map[string]chan *pb.HttpResponse
}

// SendMessage sends a message on the stream in a thread-safe manner.
func (t *TunnelConnection) SendMessage(msg *pb.TunnelMessage) error {
	t.streamMu.Lock()
	defer t.streamMu.Unlock()
	return t.Stream.Send(msg)
}

// CheckRateLimit checks if the specified number of bytes can be sent.
// Returns true if allowed, false if rate limited.
func (t *TunnelConnection) CheckRateLimit(bytes int) bool {
	if t.rateLimiter == nil {
		return true // No rate limiter configured
	}
	return t.rateLimiter.AllowN(time.Now(), bytes)
}

// newRateLimiter creates a rate limiter for the given plan.
// Returns nil if rate limiting is disabled.
func newRateLimiter(plan string) *rate.Limiter {
	var mbps int
	switch plan {
	case "pro":
		mbps = ProBandwidthMbps
	default:
		mbps = FreeBandwidthMbps
	}

	// Convert Mbps to bytes/sec: mbps * 1,000,000 / 8
	bytesPerSec := mbps * 1_000_000 / 8

	// Allow BurstSeconds of burst before rate limiting kicks in.
	// This prevents normal web browsing from hitting limits - only sustained downloads.
	burstBytes := bytesPerSec * BurstSeconds
	return rate.NewLimiter(rate.Limit(bytesPerSec), burstBytes)
}

// NewTunnelServer creates a new gRPC tunnel server
func NewTunnelServer(cfg *config.Config, userTokens map[string]string, accounts *store.AccountStore, store storage.Storage) *TunnelServer {
	if userTokens == nil {
		userTokens = make(map[string]string)
	}
	return &TunnelServer{
		tunnels:    make(map[string]*TunnelConnection),
		cfg:        cfg,
		userTokens: userTokens,
		accounts:   accounts,
		storage:    store,
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

	tunnelID := strings.ToLower(regClient.TunnelId) // Normalize to lowercase
	targetURL := regClient.TargetUrl

	// Validate tunnel ID is a valid DNS label
	if !isValidDNSLabel(tunnelID) {
		common.LogError("rejected invalid tunnel ID", "tunnel_id", tunnelID)
		respMsg := &pb.TunnelMessage{
			Message: &pb.TunnelMessage_RegisterResponse{
				RegisterResponse: &pb.RegisterResponse{
					Success:      false,
					ErrorMessage: fmt.Sprintf("Invalid tunnel ID '%s'. Must be 1-63 lowercase letters, digits, or hyphens, starting and ending with alphanumeric.", tunnelID),
				},
			},
		}
		stream.Send(respMsg)
		return fmt.Errorf("invalid tunnel ID: %s", tunnelID)
	}

	// Check for reserved subdomains
	if isReservedSubdomain(tunnelID) {
		common.LogError("rejected reserved subdomain", "tunnel_id", tunnelID)
		respMsg := &pb.TunnelMessage{
			Message: &pb.TunnelMessage_RegisterResponse{
				RegisterResponse: &pb.RegisterResponse{
					Success:      false,
					ErrorMessage: fmt.Sprintf("Subdomain '%s' is reserved. Please choose a different name.", tunnelID),
				},
			},
		}
		stream.Send(respMsg)
		return fmt.Errorf("reserved subdomain: %s", tunnelID)
	}

	common.LogInfo("client registering", "tunnel_id", tunnelID, "target", targetURL)

	var creatorEmail string
	var allowedEmails []string

	// Skip auth in public mode
	if s.cfg.PublicMode {
		common.LogInfo("public mode - skipping auth", "tunnel_id", tunnelID)
		creatorEmail = "public@tunn.local"
		allowedEmails = []string{"public@tunn.local"}
	} else if s.cfg.ClientSecret != "" && regClient.AuthToken == s.cfg.ClientSecret {
		// Client secret auth (self-hosters - master key)
		common.LogInfo("client secret auth - bypassing OAuth", "tunnel_id", tunnelID)
		creatorEmail = regClient.CreatorEmail
		if creatorEmail == "" {
			creatorEmail = "client@local"
		}
		allowedEmails = regClient.AllowedEmails
	} else if email := s.validateUserToken(regClient.AuthToken); email != "" {
		// User token auth (self-hosters - per-user from users.yaml)
		common.LogInfo("user token auth", "tunnel_id", tunnelID, "email", email)
		creatorEmail = email
		allowedEmails = regClient.AllowedEmails
	} else {
		// Validate tunnel_key (authorization to create tunnels)
		if regClient.TunnelKey != s.cfg.WellKnownKey {
			common.LogError("invalid tunnel key", "tunnel_id", tunnelID)
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

		// SECURITY: Always validate JWT and derive email from it.
		// Never trust client-provided CreatorEmail - it can be forged.
		if regClient.AuthToken == "" {
			common.LogError("no JWT provided", "tunnel_id", tunnelID)
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

		extractedEmail, err := s.validateJWTAndExtractEmail(regClient.AuthToken)
		if err != nil {
			common.LogError("JWT validation failed", "tunnel_id", tunnelID, "error", err)
			respMsg := &pb.TunnelMessage{
				Message: &pb.TunnelMessage_RegisterResponse{
					RegisterResponse: &pb.RegisterResponse{
						Success:      false,
						ErrorMessage: "Invalid or expired token. Run 'tunn login' to refresh.",
					},
				},
			}
			stream.Send(respMsg)
			return fmt.Errorf("JWT validation failed for tunnel %s: %w", tunnelID, err)
		}
		creatorEmail = extractedEmail
		allowedEmails = regClient.AllowedEmails

		common.LogInfo("tunnel registration", "tunnel_id", tunnelID, "creator", creatorEmail, "allowed", allowedEmails)
	}

	// Check subdomain reservations (if account store is available)
	if s.accounts != nil && !s.cfg.PublicMode {
		ownerAccountID, err := s.accounts.GetSubdomainOwner(tunnelID)
		if err != nil {
			common.LogError("failed to check subdomain owner", "tunnel_id", tunnelID, "error", err)
		} else if ownerAccountID != "" {
			// Subdomain is reserved - check if this user owns it
			userAccount, err := s.accounts.GetByEmail(creatorEmail)
			if err != nil || userAccount == nil || userAccount.ID != ownerAccountID {
				common.LogError("subdomain reserved by another user", "tunnel_id", tunnelID, "creator", creatorEmail)
				respMsg := &pb.TunnelMessage{
					Message: &pb.TunnelMessage_RegisterResponse{
						RegisterResponse: &pb.RegisterResponse{
							Success:      false,
							ErrorMessage: fmt.Sprintf("Subdomain '%s' is reserved by another user.", tunnelID),
						},
					},
				}
				stream.Send(respMsg)
				return fmt.Errorf("subdomain %s is reserved by another user", tunnelID)
			}
			common.LogInfo("using reserved subdomain", "tunnel_id", tunnelID, "creator", creatorEmail)
		} else {
			// Subdomain is not reserved - try to claim it if user is Pro
			userAccount, err := s.accounts.GetByEmail(creatorEmail)
			if err == nil && userAccount != nil && userAccount.Plan == "pro" {
				// Try to reserve the subdomain for this user
				if err := s.accounts.ReserveSubdomain(userAccount.ID, tunnelID); err == nil {
					common.LogInfo("auto-claimed subdomain for Pro user", "tunnel_id", tunnelID, "creator", creatorEmail)
				}
				// If reservation fails (e.g., max limit), just continue without reserving
			}
		}
	}

	// Look up plan and accountID for quota enforcement (default to "free" if lookup fails)
	plan := "free"
	var accountID string
	if s.storage != nil && s.storage.Available() && creatorEmail != "" {
		// Cross-node: use storage interface (proxies to login node if needed)
		if account, err := s.storage.GetAccountByEmail(stream.Context(), creatorEmail); err == nil && account != nil {
			plan = account.Plan
			accountID = account.ID
		}
	} else if s.accounts != nil && creatorEmail != "" {
		// Local fallback: direct account store access
		if account, err := s.accounts.GetByEmail(creatorEmail); err == nil && account != nil {
			plan = account.Plan
			accountID = account.ID
		}
	}

	// Create tunnel connection
	conn := &TunnelConnection{
		TunnelID:        tunnelID,
		TargetURL:       targetURL,
		Stream:          stream,
		Connected:       time.Now(),
		CreatorEmail:    creatorEmail,
		AccountID:       accountID,
		AllowedEmails:   allowedEmails,
		Plan:            plan,
		rateLimiter:     newRateLimiter(plan),
		pendingRequests: make(map[string]chan *pb.HttpResponse),
	}

	// Check if tunnel exists locally first
	s.mu.Lock()
	if _, exists := s.tunnels[tunnelID]; exists {
		s.mu.Unlock()
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
	s.mu.Unlock()

	// Register tunnel and check limits (cross-node if available)
	var registeredWithStorage bool
	if s.storage != nil && s.storage.Available() && accountID != "" {
		// Cross-node: register with login node (includes duplicate and limit checks)
		reg, err := s.storage.RegisterTunnel(stream.Context(), tunnelID, accountID, s.cfg.Domain)
		if err != nil {
			common.LogError("failed to register tunnel with login node", "tunnel_id", tunnelID, "error", err)
			// Fall back to local check
		} else if !reg.Allowed {
			respMsg := &pb.TunnelMessage{
				Message: &pb.TunnelMessage_RegisterResponse{
					RegisterResponse: &pb.RegisterResponse{
						Success:      false,
						ErrorMessage: reg.Reason,
					},
				},
			}
			stream.Send(respMsg)
			common.LogInfo("tunnel registration denied", "tunnel_id", tunnelID, "reason", reg.Reason)
			return fmt.Errorf("tunnel registration denied: %s", reg.Reason)
		} else {
			registeredWithStorage = true
			common.LogDebug("tunnel registered with login node", "tunnel_id", tunnelID, "count", reg.CurrentCount, "max", reg.MaxAllowed)
		}
	}

	// If cross-node registration didn't happen, check limits locally
	if !registeredWithStorage {
		maxTunnels := storage.FreeTunnelLimit
		if plan == "pro" {
			maxTunnels = storage.ProTunnelLimit
		}
		s.mu.Lock()
		currentCount := s.countTunnelsForEmail(creatorEmail)
		if currentCount >= maxTunnels {
			s.mu.Unlock()
			respMsg := &pb.TunnelMessage{
				Message: &pb.TunnelMessage_RegisterResponse{
					RegisterResponse: &pb.RegisterResponse{
						Success:      false,
						ErrorMessage: fmt.Sprintf("tunnel limit reached (%d/%d)", currentCount, maxTunnels),
					},
				},
			}
			stream.Send(respMsg)
			common.LogInfo("tunnel limit reached", "email", creatorEmail, "count", currentCount, "max", maxTunnels)
			return fmt.Errorf("tunnel limit reached for %s", creatorEmail)
		}
		s.mu.Unlock()
	}

	// Add to local map (re-check for race condition)
	s.mu.Lock()
	if _, exists := s.tunnels[tunnelID]; exists {
		s.mu.Unlock()
		// Unregister from storage if we registered
		if registeredWithStorage && s.storage != nil {
			s.storage.UnregisterTunnel(stream.Context(), tunnelID)
		}
		respMsg := &pb.TunnelMessage{
			Message: &pb.TunnelMessage_RegisterResponse{
				RegisterResponse: &pb.RegisterResponse{
					Success:      false,
					ErrorMessage: "tunnel ID already in use",
				},
			},
		}
		stream.Send(respMsg)
		return fmt.Errorf("tunnel ID %s already registered (race)", tunnelID)
	}
	s.tunnels[tunnelID] = conn
	s.mu.Unlock()

	// Cleanup on disconnect
	defer func() {
		s.mu.Lock()
		delete(s.tunnels, tunnelID)
		s.mu.Unlock()

		// Unregister from login node if we registered
		if registeredWithStorage && s.storage != nil && s.storage.Available() {
			if err := s.storage.UnregisterTunnel(context.Background(), tunnelID); err != nil {
				common.LogError("failed to unregister tunnel from login node", "tunnel_id", tunnelID, "error", err)
			}
		}

		common.LogInfo("tunnel disconnected", "tunnel_id", tunnelID)
	}()

	// Send success response
	publicURL := fmt.Sprintf("https://%s.%s", tunnelID, s.cfg.Domain)
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
			// Respond to health check (use conn.SendMessage for thread safety)
			s.handleHealthCheck(conn, m.HealthCheck)

		case *pb.TunnelMessage_HttpResponse:
			// HTTP response from client - route to waiting request
			conn.pendingMu.RLock()
			respChan, exists := conn.pendingRequests[m.HttpResponse.ConnectionId]
			conn.pendingMu.RUnlock()

			if exists {
				select {
				case respChan <- m.HttpResponse:
					common.LogDebug("routed http response",
						"tunnel_id", tunnelID,
						"connection_id", m.HttpResponse.ConnectionId,
						"status", m.HttpResponse.StatusCode)
				default:
					common.LogDebug("response channel full, dropping response",
						"tunnel_id", tunnelID,
						"connection_id", m.HttpResponse.ConnectionId)
				}
			} else {
				common.LogDebug("no pending request for http response",
					"tunnel_id", tunnelID,
					"connection_id", m.HttpResponse.ConnectionId)
			}

		default:
			common.LogInfo("unexpected message type", "type", fmt.Sprintf("%T", m))
		}
	}
}

// handleHealthCheck responds to health check pings
func (s *TunnelServer) handleHealthCheck(conn *TunnelConnection, hc *pb.HealthCheck) {
	response := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_HealthCheckResponse{
			HealthCheckResponse: &pb.HealthCheckResponse{
				Timestamp:         hc.Timestamp,
				ResponseTimestamp: time.Now().UnixMilli(),
			},
		},
	}

	// Use SendMessage for thread-safe sending (concurrent with HTTP request handlers)
	if err := conn.SendMessage(response); err != nil {
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

// countTunnelsForEmail counts active tunnels owned by a specific email.
// Must be called with s.mu held (read or write lock).
func (s *TunnelServer) countTunnelsForEmail(email string) int {
	count := 0
	for _, conn := range s.tunnels {
		if conn.CreatorEmail == email {
			count++
		}
	}
	return count
}

// validateUserToken checks if a token matches any user in users.yaml
// Returns the email if valid, empty string if not
// Uses constant-time comparison to prevent timing attacks
func (s *TunnelServer) validateUserToken(token string) string {
	if token == "" || len(s.userTokens) == 0 {
		return ""
	}
	for email, userToken := range s.userTokens {
		if subtle.ConstantTimeCompare([]byte(userToken), []byte(token)) == 1 {
			return email
		}
	}
	return ""
}

// validateJWTAndExtractEmail validates a JWT signature and extracts the email claim
// Returns the email if valid, or an error if the JWT is invalid or unsigned
func (s *TunnelServer) validateJWTAndExtractEmail(tokenString string) (string, error) {
	if s.cfg.JWTSecret == "" {
		return "", fmt.Errorf("JWT validation not configured")
	}

	// Parse and validate token with signature verification
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.JWTSecret), nil
	})

	if err != nil {
		return "", fmt.Errorf("invalid JWT: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("JWT signature validation failed")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid JWT claims format")
	}

	// Extract email
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return "", fmt.Errorf("email claim not found or empty in JWT")
	}

	return email, nil
}
