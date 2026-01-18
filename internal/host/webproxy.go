package host

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// MaxBodySize is the maximum request/response body size (100 MB).
// Prevents memory exhaustion from large requests.
const MaxBodySize = 100 * 1024 * 1024

// platformCookies lists cookies that should NOT be forwarded to tunnel targets.
// These are tunn platform cookies that tunnel owners should never see.
var platformCookies = map[string]bool{
	"tunn_session": true,
}

// stripPlatformCookies removes platform cookies from a Cookie header value.
// Returns the sanitized cookie string, or empty if no cookies remain.
func stripPlatformCookies(cookieHeader string) string {
	if cookieHeader == "" {
		return ""
	}

	var kept []string
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Cookie format: name=value
		name := part
		if idx := strings.Index(part, "="); idx > 0 {
			name = part[:idx]
		}
		if !platformCookies[name] {
			kept = append(kept, part)
		}
	}

	if len(kept) == 0 {
		return ""
	}
	return strings.Join(kept, "; ")
}

// handleWebProxy handles incoming web requests to tunnel subdomains
func (p *ProxyServer) handleWebProxy(w http.ResponseWriter, r *http.Request) {
	// Extract tunnel ID from hostname
	tunnelID := extractTunnelID(r.Host, p.Domain)

	// If this is the apex domain (no tunnel ID), show info page
	if tunnelID == "" {
		p.handleApexDomain(w, r)
		return
	}

	// 1. Check if tunnel is local
	if _, exists := p.tunnelServer.GetTunnel(tunnelID); exists {
		p.proxyToLocal(w, r, tunnelID)
		return
	}

	// 2. Check cache for remote tunnel
	p.cacheMu.RLock()
	nodeAddr, cached := p.tunnelCache[tunnelID]
	p.cacheMu.RUnlock()

	if cached {
		common.LogInfo("proxying to cached node", "tunnel_id", tunnelID, "node_addr", nodeAddr)
		p.proxyToNode(w, r, nodeAddr)
		return
	}

	// 3. Probe other nodes
	for addr, client := range p.nodeClients {
		common.LogInfo("probing node for tunnel", "tunnel_id", tunnelID, "node_addr", addr)
		resp, err := client.FindTunnel(context.Background(), &internalv1.FindTunnelRequest{TunnelId: tunnelID})
		if err != nil {
			common.LogError("failed to probe node", "error", err, "node_addr", addr)
			continue
		}

		if resp.Found {
			common.LogInfo("tunnel found on remote node", "tunnel_id", tunnelID, "node_addr", resp.NodeAddress)
			// Cache the result
			p.cacheMu.Lock()
			p.tunnelCache[tunnelID] = resp.NodeAddress
			p.cacheMu.Unlock()

			p.proxyToNode(w, r, resp.NodeAddress)
			return
		}
	}

	// 4. If not found anywhere, return an error
	common.LogInfo("tunnel not found on any node", "tunnel_id", tunnelID, "host", r.Host)
	http.Error(w, "Tunnel not found or offline", http.StatusServiceUnavailable)
}

// proxyToLocal handles proxying for a tunnel hosted on the current node
func (p *ProxyServer) proxyToLocal(w http.ResponseWriter, r *http.Request, tunnelID string) {
	tunnel, _ := p.tunnelServer.GetTunnel(tunnelID)

	common.LogDebug("proxying web request locally",
		"tunnel_id", tunnelID,
		"target", tunnel.TargetURL,
		"path", r.URL.Path,
		"method", r.Method)

	// Skip auth in public mode
	if !p.config.PublicMode {
		// Check authentication (web requests require a session)
		authenticated := p.sessionManager.GetBool(r.Context(), "authenticated")
		if !authenticated {
			// Redirect to login with return_to parameter (URL escaped)
			returnTo := r.URL.String()
			loginURL := fmt.Sprintf("/auth/login?return_to=%s", url.QueryEscape(returnTo))

			common.LogInfo("unauthenticated tunnel access, redirecting to login",
				"tunnel_id", tunnelID,
				"return_to", returnTo)
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		// User is authenticated, proceed with proxying
		userEmail := p.sessionManager.GetString(r.Context(), "user_email")
		common.LogDebug("authenticated tunnel access",
			"email", userEmail,
			"tunnel_id", tunnelID,
			"path", r.URL.Path)

		// Get user's email bucket (all emails associated with their account)
		userEmails := []string{userEmail}
		if p.storage.Available() {
			if bucket, err := p.storage.GetEmailBucket(r.Context(), userEmail); err == nil {
				userEmails = bucket
			}
		}

		// Check if any email in user's bucket is on the tunnel's allow-list
		allowed := isEmailBucketAllowed(userEmails, tunnel.AllowedEmails)

		if !allowed {
			common.LogInfo("access denied - user not on allow-list",
				"email", userEmail,
				"bucket", userEmails,
				"tunnel_id", tunnelID,
				"allowed_emails", tunnel.AllowedEmails)

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			writePageStart(w, "tunn - Access Denied")
			fmt.Fprintf(w, `<h1 class="error-title">Access denied</h1>
<p>You (<code>%s</code>) are not authorized to access this tunnel.</p>
<p>Contact the tunnel owner to request access.</p>
`, userEmail)
			writePageEnd(w)
			return
		}

		common.LogDebug("allow-list check passed",
			"email", userEmail,
			"tunnel_id", tunnelID)
	} else {
		common.LogDebug("public mode - skipping auth", "tunnel_id", tunnelID)
	}

	// Check quota before proxying (skip in public mode since there's no creator to bill)
	if !p.config.PublicMode && tunnel.CreatorEmail != "" {
		if !p.CheckQuota(r.Context(), tunnel.CreatorEmail, tunnel.Plan) {
			common.LogInfo("quota exceeded, rejecting request",
				"tunnel_id", tunnelID,
				"creator", tunnel.CreatorEmail,
				"plan", tunnel.Plan)
			http.Error(w, "Quota exceeded - tunnel owner's monthly limit reached", http.StatusTooManyRequests)
			return
		}
	}

	// Proxy the HTTP request over gRPC
	if err := p.proxyHTTPOverGRPC(w, r, tunnel); err != nil {
		common.LogError("failed to proxy request", "error", err, "tunnel_id", tunnelID)
		http.Error(w, "Failed to proxy request", http.StatusBadGateway)
		return
	}
}

// proxyHTTPOverGRPC forwards an HTTP request over the gRPC tunnel and writes the response
func (p *ProxyServer) proxyHTTPOverGRPC(w http.ResponseWriter, r *http.Request, tunnel *TunnelConnection) error {
	// Generate unique connection ID
	connectionID, err := generateConnectionID()
	if err != nil {
		return fmt.Errorf("failed to generate connection ID: %w", err)
	}

	// Read request body with size limit to prevent memory exhaustion
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodySize))
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	// Convert headers to map (join multi-value headers per HTTP spec)
	// SECURITY: Strip platform cookies to prevent tunnel owners from stealing sessions
	headers := make(map[string]string)
	for key, values := range r.Header {
		value := strings.Join(values, ", ")
		if strings.EqualFold(key, "Cookie") {
			value = stripPlatformCookies(value)
			if value == "" {
				continue // Don't include empty Cookie header
			}
		}
		headers[key] = value
	}

	// Create HttpRequest message
	httpReq := &pb.HttpRequest{
		ConnectionId: connectionID,
		Method:       r.Method,
		Path:         r.URL.RequestURI(),
		Headers:      headers,
		Body:         body,
	}

	// Create response channel and register it
	respChan := make(chan *pb.HttpResponse, 1)
	tunnel.pendingMu.Lock()
	tunnel.pendingRequests[connectionID] = respChan
	tunnel.pendingMu.Unlock()

	// Cleanup on return - remove from map so no new sends can happen
	// Note: We don't close the channel to avoid "send on closed channel" panic.
	// The gRPC receive loop may still have a reference and try to send.
	// The channel will be GC'd after removal from the map.
	defer func() {
		tunnel.pendingMu.Lock()
		delete(tunnel.pendingRequests, connectionID)
		tunnel.pendingMu.Unlock()
	}()

	// Send HttpRequest to client
	msg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_HttpRequest{
			HttpRequest: httpReq,
		},
	}

	if err := tunnel.SendMessage(msg); err != nil {
		return fmt.Errorf("failed to send http request: %w", err)
	}

	common.LogDebug("sent http request to client",
		"connection_id", connectionID,
		"method", r.Method,
		"path", r.URL.Path)

	// Wait for response with timeout
	timeout := 30 * time.Second
	select {
	case httpResp := <-respChan:
		// Check bandwidth rate limit (request + response)
		totalSize := len(body) + len(httpResp.Body)
		if !tunnel.CheckRateLimit(totalSize) {
			common.LogInfo("bandwidth rate limit exceeded",
				"connection_id", connectionID,
				"tunnel_id", tunnel.TunnelID,
				"bytes", totalSize)
			http.Error(w, "Bandwidth rate limit exceeded", http.StatusTooManyRequests)
			return nil // Return nil - we handled the error by sending 429
		}

		// Write response headers
		for key, value := range httpResp.Headers {
			w.Header().Set(key, value)
		}

		// Write status code
		w.WriteHeader(int(httpResp.StatusCode))

		// Write body
		if _, err := w.Write(httpResp.Body); err != nil {
			return fmt.Errorf("failed to write response body: %w", err)
		}

		common.LogDebug("proxied http response",
			"connection_id", connectionID,
			"status", httpResp.StatusCode,
			"body_size", len(httpResp.Body))

		// Record usage (request body + response body)
		if tunnel.CreatorEmail != "" {
			p.RecordUsage(r.Context(), tunnel.CreatorEmail, int64(totalSize))
		}

		return nil

	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for response after %v", timeout)
	}
}

// generateConnectionID creates a random connection ID
func generateConnectionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// proxyToNode handles proxying a request to another node in the cluster
func (p *ProxyServer) proxyToNode(w http.ResponseWriter, r *http.Request, nodeAddr string) {
	target, err := url.Parse("https://" + nodeAddr)
	if err != nil {
		common.LogError("failed to parse node address", "error", err, "node_addr", nodeAddr)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// CRITICAL: Preserve original Host header so remote node can extract tunnel ID.
	// NewSingleHostReverseProxy's default Director rewrites Host to target.Host,
	// but the remote node needs the original subdomain (e.g., abc123.tunn.to).
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalHost := req.Host // Save original before Director modifies it
		originalDirector(req)
		req.Host = originalHost // Restore original Host
	}

	// We need to create a custom transport to skip TLS verification if needed,
	// since we are using self-signed certs in development.
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: p.config.SkipVerify},
	}

	common.LogInfo("proxying to remote node", "target", target.String())
	proxy.ServeHTTP(w, r)
}

// handleApexDomain handles requests to the apex domain (e.g., tunn.to)
func (p *ProxyServer) handleApexDomain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	switch r.URL.Path {
	case "/privacy":
		fmt.Fprint(w, privacyHTML)
	case "/terms":
		fmt.Fprint(w, termsHTML)
	default:
		fmt.Fprint(w, homepageHTML)
	}
}

// isEmailAllowed checks if an email is on the allow-list
// Supports both exact matches ("alice@example.com") and domain wildcards ("@example.com")
func isEmailAllowed(email string, allowList []string) bool {
	for _, allowed := range allowList {
		if strings.HasPrefix(allowed, "@") {
			// Domain wildcard: check if email ends with this domain
			if strings.HasSuffix(strings.ToLower(email), strings.ToLower(allowed)) {
				return true
			}
		} else {
			// Exact match (case-insensitive)
			if strings.EqualFold(email, allowed) {
				return true
			}
		}
	}
	return false
}

// isEmailBucketAllowed checks if any email in the bucket is on the allow-list
// This supports the identity model where users may have multiple verified emails
func isEmailBucketAllowed(userEmails []string, allowList []string) bool {
	for _, email := range userEmails {
		if isEmailAllowed(email, allowList) {
			return true
		}
	}
	return false
}
