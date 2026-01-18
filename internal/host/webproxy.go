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
			// Redirect to login with return_to parameter
			returnTo := r.URL.String()
			loginURL := fmt.Sprintf("/auth/login?return_to=%s", returnTo)

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
		if !p.CheckQuota(r.Context(), tunnel.CreatorEmail, "free") {
			common.LogInfo("quota exceeded, rejecting request",
				"tunnel_id", tunnelID,
				"creator", tunnel.CreatorEmail)
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

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	// Convert headers to map (join multi-value headers per HTTP spec)
	headers := make(map[string]string)
	for key, values := range r.Header {
		headers[key] = strings.Join(values, ", ")
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

	// Cleanup on return
	defer func() {
		tunnel.pendingMu.Lock()
		delete(tunnel.pendingRequests, connectionID)
		tunnel.pendingMu.Unlock()
		close(respChan)
	}()

	// Send HttpRequest to client
	msg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_HttpRequest{
			HttpRequest: httpReq,
		},
	}

	if err := tunnel.Stream.Send(msg); err != nil {
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
			totalBytes := int64(len(body) + len(httpResp.Body))
			p.RecordUsage(r.Context(), tunnel.CreatorEmail, totalBytes)
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
