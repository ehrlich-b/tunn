package host

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"google.golang.org/grpc/metadata"
)

// Keep registration and custom-domain binding on the same name policy.
var reservedSubdomains = common.ReservedTunnelNames

func isReservedSubdomain(tunnelID string) bool { return common.IsReservedTunnelName(tunnelID) }

// isValidDNSLabel checks if a tunnel ID is a valid DNS label per RFC 1123.
// Must be 1-63 chars, contain only lowercase letters, digits, hyphens,
// and start/end with alphanumeric.
func isValidDNSLabel(tunnelID string) bool {
	if len(tunnelID) == 0 || len(tunnelID) > 63 {
		return false
	}

	// Must start with alphanumeric
	first := tunnelID[0]
	if (first < 'a' || first > 'z') && (first < '0' || first > '9') {
		return false
	}

	// Must end with alphanumeric
	last := tunnelID[len(tunnelID)-1]
	if (last < 'a' || last > 'z') && (last < '0' || last > '9') {
		return false
	}

	// Middle chars can be alphanumeric or hyphen
	for i := 1; i < len(tunnelID)-1; i++ {
		c := tunnelID[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}

	return true
}

// TunnelServer implements the gRPC TunnelService
type TunnelServer struct {
	pb.UnimplementedTunnelServiceServer

	hosts      *store.HostStore
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
	HostID             string
	TunnelID           string
	TargetURL          string
	Stream             pb.TunnelService_EstablishTunnelServer
	Connected          time.Time
	CreatorEmail       string
	AccountID          string   // Account ID for usage tracking (from storage)
	accountQuotaExempt bool     // Explicit self-hosted authentication without an account
	AllowedEmails      []string // Includes creator_email + any additional allowed emails
	AccessTokenSHA256  []byte   // Endpoint-scoped bearer digest; plaintext never reaches the relay
	Capabilities       map[string]bool
	EndpointProtocol   string
	Plan               string // "free" or "pro" - cached for quota checks

	// Bandwidth rate limiter (token bucket)
	rateLimiter *rate.Limiter

	// Stream send mutex - gRPC streams are NOT thread-safe for concurrent Send()
	streamMu sync.Mutex
	authMu   sync.RWMutex

	// HTTP request tracking
	pendingMu       sync.RWMutex
	pendingRequests map[string]chan *pb.HttpResponse
	pendingStreams  map[string]*pendingConnection
}

// Supports reports whether the connected client advertised a data-plane
// capability during registration.
func (t *TunnelConnection) Supports(capability string) bool {
	return t.Capabilities[capability]
}

func (t *TunnelConnection) accessTokenDigest() []byte {
	t.authMu.RLock()
	defer t.authMu.RUnlock()
	return append([]byte(nil), t.AccessTokenSHA256...)
}

func (t *TunnelConnection) updateAccessTokenDigest(digest []byte) {
	t.authMu.Lock()
	t.AccessTokenSHA256 = append(t.AccessTokenSHA256[:0], digest...)
	t.authMu.Unlock()
	// Revocation includes upgraded sockets using the previous capability.
	// Cookie-authenticated sockets have no capability digest.
	t.pendingMu.RLock()
	defer t.pendingMu.RUnlock()
	for _, pending := range t.pendingStreams {
		if len(pending.accessDigest) > 0 && !bytes.Equal(pending.accessDigest, digest) {
			pending.stop()
		}
	}
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

	hostID := ""
	if md, ok := metadata.FromIncomingContext(stream.Context()); ok {
		if ids := md.Get("tunn-host-id"); len(ids) > 0 {
			hostID = ids[0]
		}
	}
	if hostID != "" && (!s.cfg.HostModeEnabled || s.hosts == nil) {
		_ = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: false, ErrorMessage: "host mode is disabled on this relay"}}})
		return fmt.Errorf("host mode is disabled")
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
		_ = stream.Send(respMsg)
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
		_ = stream.Send(respMsg)
		return fmt.Errorf("reserved subdomain: %s", tunnelID)
	}

	if size := len(regClient.AccessTokenSha256); size != 0 && size != sha256.Size {
		common.LogError("rejected invalid endpoint token digest", "tunnel_id", tunnelID, "size", size)
		respMsg := &pb.TunnelMessage{
			Message: &pb.TunnelMessage_RegisterResponse{
				RegisterResponse: &pb.RegisterResponse{
					Success:      false,
					ErrorMessage: "Invalid endpoint access token digest.",
				},
			},
		}
		_ = stream.Send(respMsg)
		return fmt.Errorf("invalid endpoint token digest for tunnel %s", tunnelID)
	}
	endpointProtocol := regClient.EndpointProtocol
	if endpointProtocol == "" {
		endpointProtocol = "http"
	}
	if endpointProtocol != "http" && endpointProtocol != "tcp" {
		_ = stream.Send(&pb.TunnelMessage{
			Message: &pb.TunnelMessage_RegisterResponse{
				RegisterResponse: &pb.RegisterResponse{
					Success:      false,
					ErrorMessage: "Unsupported endpoint protocol.",
				},
			},
		})
		return fmt.Errorf("unsupported endpoint protocol %q", endpointProtocol)
	}
	if endpointProtocol == "tcp" && !stringSliceContains(regClient.Capabilities, common.CapabilityConnectionStreamV1) {
		_ = stream.Send(&pb.TunnelMessage{
			Message: &pb.TunnelMessage_RegisterResponse{
				RegisterResponse: &pb.RegisterResponse{
					Success:      false,
					ErrorMessage: "TCP endpoints require connection-stream-v1 support.",
				},
			},
		})
		return fmt.Errorf("TCP client does not support connection streams")
	}

	common.LogInfo("client registering", "tunnel_id", tunnelID, "target", targetURL)

	var creatorEmail string
	var allowedEmails []string
	var requiresAccount bool

	// Skip auth in public mode
	if s.cfg.PublicMode {
		common.LogInfo("public mode - skipping auth", "tunnel_id", tunnelID)
		creatorEmail = "public@tunn.local"
		// PublicMode controls publisher authentication for local/self-hosted
		// development. It must not silently turn every published endpoint into
		// an allow-listed endpoint: an empty client allow-list means visitors can
		// reach it anonymously, while an explicit allow-list is still preserved.
		allowedEmails = regClient.AllowedEmails
	} else if s.cfg.ClientSecret != "" && regClient.AuthToken == s.cfg.ClientSecret {
		// Client secret auth (self-hosters - master key)
		common.LogInfo("client secret auth - bypassing OAuth", "tunnel_id", tunnelID)
		creatorEmail = regClient.CreatorEmail
		if hostID != "" {
			creatorEmail = "client@local"
		}
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
			_ = stream.Send(respMsg)
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
			_ = stream.Send(respMsg)
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
			_ = stream.Send(respMsg)
			return fmt.Errorf("JWT validation failed for tunnel %s: %w", tunnelID, err)
		}
		creatorEmail = extractedEmail
		allowedEmails = regClient.AllowedEmails
		requiresAccount = true

		common.LogInfo("tunnel registration", "tunnel_id", tunnelID, "creator", creatorEmail, "allowed", allowedEmails)
	}

	// Resolve hosted publishers through shared storage; unknown ownership fails closed.
	plan := "free"
	var accountID string
	if requiresAccount {
		if s.storage == nil || !s.storage.Available() {
			return rejectTunnelRegistration(stream, "Account service temporarily unavailable.")
		}
		account, err := s.storage.GetAccountByEmail(stream.Context(), creatorEmail)
		if err != nil || account == nil || account.ID == "" {
			return rejectTunnelRegistration(stream, "Account could not be verified. Run 'tunn login' again.")
		}
		plan = account.Plan
		accountID = account.ID
	}

	if hostID != "" {
		account, err := s.hostAccount(regClient.AuthToken, false)
		kind := targetURL
		if kind == "unix-http" {
			kind = "unix"
		}
		expectedProtocol := "http"
		if targetURL == "tcp" || targetURL == "unix" {
			expectedProtocol = "tcp"
		}
		if err == nil && account != nil {
			accountID, plan = account.ID, account.Plan
			err = s.hosts.CheckEndpoint(accountID, hostID, tunnelID, kind)
			if endpointProtocol != expectedProtocol {
				err = fmt.Errorf("host endpoint protocol mismatch")
			}
		} else if err == nil {
			err = fmt.Errorf("host must be registered before publishing")
		}
		if err != nil || len(allowedEmails) == 0 {
			_ = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: false, ErrorMessage: "private host endpoint does not match its reservation"}}})
			return fmt.Errorf("invalid host registration")
		}
	}

	// Create tunnel connection
	capabilities := make(map[string]bool, len(regClient.Capabilities))
	for _, capability := range regClient.Capabilities {
		capabilities[capability] = true
	}
	conn := &TunnelConnection{
		HostID:             hostID,
		TunnelID:           tunnelID,
		TargetURL:          targetURL,
		Stream:             stream,
		Connected:          time.Now(),
		CreatorEmail:       creatorEmail,
		AccountID:          accountID,
		accountQuotaExempt: !requiresAccount && hostID == "",
		AllowedEmails:      allowedEmails,
		AccessTokenSHA256:  append([]byte(nil), regClient.AccessTokenSha256...),
		Capabilities:       capabilities,
		EndpointProtocol:   endpointProtocol,
		Plan:               plan,
		rateLimiter:        newRateLimiter(plan),
		pendingRequests:    make(map[string]chan *pb.HttpResponse),
		pendingStreams:     make(map[string]*pendingConnection),
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
		_ = stream.Send(respMsg)
		return fmt.Errorf("tunnel ID %s already registered", tunnelID)
	}
	s.mu.Unlock()

	// Register tunnel and check limits (cross-node if available)
	var registeredWithStorage bool
	if s.storage != nil && accountID != "" {
		// Cross-node: register with login node (includes duplicate and limit checks)
		reg, err := s.storage.RegisterTunnel(stream.Context(), tunnelID, accountID, s.cfg.Domain)
		if err != nil {
			common.LogError("failed to register tunnel with login node", "tunnel_id", tunnelID, "error", err)
			return rejectTunnelRegistration(stream, "Tunnel ownership could not be verified. Please try again later.")
		} else if !reg.Allowed {
			respMsg := &pb.TunnelMessage{
				Message: &pb.TunnelMessage_RegisterResponse{
					RegisterResponse: &pb.RegisterResponse{
						Success:      false,
						ErrorMessage: reg.Reason,
					},
				},
			}
			_ = stream.Send(respMsg)
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
			_ = stream.Send(respMsg)
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
			if err := s.storage.UnregisterTunnel(stream.Context(), tunnelID); err != nil {
				common.LogError("failed to unregister duplicate tunnel", "tunnel_id", tunnelID, "error", err)
			}
		}
		respMsg := &pb.TunnelMessage{
			Message: &pb.TunnelMessage_RegisterResponse{
				RegisterResponse: &pb.RegisterResponse{
					Success:      false,
					ErrorMessage: "tunnel ID already in use",
				},
			},
		}
		_ = stream.Send(respMsg)
		return fmt.Errorf("tunnel ID %s already registered (race)", tunnelID)
	}
	// Recheck durable ownership while holding the same lock used by host
	// reservation. This closes the race between ephemeral admission and reserve.
	if s.accounts != nil && !s.cfg.PublicMode {
		owner, err := s.accounts.GetSubdomainOwner(tunnelID)
		if err != nil || (owner != "" && owner != accountID) {
			s.mu.Unlock()
			if registeredWithStorage {
				_ = s.storage.UnregisterTunnel(context.Background(), tunnelID)
			}
			_ = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: false, ErrorMessage: "name reservation could not be verified"}}})
			return fmt.Errorf("name reservation could not be verified")
		}
	}
	// The tunnel becomes visible before the registration reply reaches the
	// publisher. Hold its send lock so an incoming request cannot overtake
	// RegisterResponse on the same gRPC stream.
	conn.streamMu.Lock()
	s.tunnels[tunnelID] = conn
	s.mu.Unlock()

	s.hostSeen(conn)

	// Cleanup on disconnect
	defer func() {
		s.hostSeen(conn)
		conn.closePendingConnections()
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
				Success:      true,
				PublicUrl:    publicURL,
				Capabilities: []string{common.CapabilityHTTPStreamV1, common.CapabilityConnectionStreamV1, common.CapabilityWebSocketV1},
			},
		},
	}

	err = stream.Send(respMsg)
	conn.streamMu.Unlock()
	if err != nil {
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

		case *pb.TunnelMessage_ConnectionAccept,
			*pb.TunnelMessage_ConnectionData,
			*pb.TunnelMessage_ConnectionHalfClose,
			*pb.TunnelMessage_ConnectionClose:
			conn.routeConnectionMessage(msg)

		case *pb.TunnelMessage_UpdateAccessToken:
			if len(m.UpdateAccessToken.AccessTokenSha256) != sha256.Size {
				return fmt.Errorf("invalid rotated endpoint token digest")
			}
			conn.updateAccessTokenDigest(m.UpdateAccessToken.AccessTokenSha256)
			common.LogInfo("endpoint access token rotated", "tunnel_id", tunnelID)

		default:
			common.LogInfo("unexpected message type", "type", fmt.Sprintf("%T", m))
		}
	}
}

func stringSliceContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// handleHealthCheck responds to health check pings
func (s *TunnelServer) handleHealthCheck(conn *TunnelConnection, hc *pb.HealthCheck) {
	s.hostSeen(conn)
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
	return identityEmail(claims)
}

// rejectTunnelRegistration sends a failed reply before terminating the stream.
func rejectTunnelRegistration(stream pb.TunnelService_EstablishTunnelServer, reason string) error {
	_ = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{
		RegisterResponse: &pb.RegisterResponse{Success: false, ErrorMessage: reason},
	}})
	return fmt.Errorf("tunnel registration denied: %s", reason)
}
