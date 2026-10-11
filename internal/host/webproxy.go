package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/metering"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// MaxBodySize is the maximum request/response body size (100 MB).
// Prevents memory exhaustion from large requests.
const MaxBodySize = 100 * 1024 * 1024

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
			name = strings.TrimSpace(part[:idx])
		}
		if !isPlatformCookie(name) {
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
	tunnelID := extractTunnelID(requestHostname(r.Host), p.Domain)
	if p.customerHost(r.Host) {
		if p.domains == nil {
			http.NotFound(w, r)
			return
		}
		binding, err := p.domains.Route(r.Context(), &domainpb.Domain{Name: requestHostname(r.Host)})
		if err != nil {
			domainHTTPError(w, err)
			return
		}
		tunnelID = binding.Tunnel
		r = r.WithContext(context.WithValue(r.Context(), domainOwnerKey{}, binding.Owner))
	}

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
		p.proxyToNode(w, r, nodeAddr, tunnelID)
		return
	}

	// 3. Probe other nodes (with timeout to prevent slow nodes from blocking)
	for addr, client := range p.nodeClients {
		common.LogInfo("probing node for tunnel", "tunnel_id", tunnelID, "node_addr", addr)
		probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := client.FindTunnel(probeCtx, &internalv1.FindTunnelRequest{TunnelId: tunnelID})
		cancel()
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

			p.proxyToNode(w, r, resp.NodeAddress, tunnelID)
			return
		}
	}

	// 4. If not found anywhere, return an error
	common.LogInfo("tunnel not found on any node", "tunnel_id", tunnelID, "host", r.Host)
	if p.meter != nil {
		id, err := generateConnectionID()
		if err == nil {
			w.Header().Set("Tunn-Request-ID", id)
			_, err = p.meter.Admit(r.Context(), &meterpb.Event{RequestId: id, Endpoint: tunnelID, Caller: "anonymous", AuthMethod: "none", Reason: "endpoint_offline", Status: 503})
			if err != nil {
				p.operations.drops.Add(1)
				common.LogError("failed to audit offline endpoint", "request_id", id, "error", err)
			}
		}
	}
	http.Error(w, "Tunnel not found or offline", http.StatusServiceUnavailable)
}

// proxyToLocal handles proxying for a tunnel hosted on the current node
func (p *ProxyServer) proxyToLocal(w http.ResponseWriter, r *http.Request, tunnelID string) {
	tunnel, exists := p.tunnelServer.GetTunnel(tunnelID)
	if !exists {
		http.Error(w, "Tunnel offline", 503)
		return
	}
	account, accountErr := p.currentTunnelAccount(r.Context(), tunnel)
	if owner, ok := r.Context().Value(domainOwnerKey{}).(string); ok && (owner == "" || account == nil || account.ID != owner) {
		http.Error(w, "Domain tunnel ownership mismatch", http.StatusForbidden)
		return
	}
	session := newIngressMeter(p, tunnel)
	if account != nil {
		session.accountID, session.event.Owner = account.ID, account.ID
		tunnel.updateBandwidthPlan(account.Plan)
	}
	meterWriter := &meterResponseWriter{ResponseWriter: w, meter: session, ctx: r.Context(), status: 200}
	w = meterWriter
	if p.meter != nil {
		w.Header().Set("Tunn-Request-ID", session.event.RequestId)
	}
	defer session.complete(r.Context(), meterWriter)
	grantAuthenticated := false
	// A known suspension rejects every credential path. Unresolved ownership
	// still follows authentication and the existing fail-closed quota check.
	if !tunnel.accountQuotaExempt && accountErr == nil && account != nil && account.OperationalState != "" && account.OperationalState != "active" {
		session.reason = "account_suspended"
		w.Header().Set("Tunn-Limit-Reason", session.reason)
		http.Error(w, session.reason, 403)
		return
	}
	if token, header := grantBearer(r); token != "" {
		if p.meter == nil {
			session.reason = "meter_unavailable"
			http.Error(w, "Usage ledger unavailable", 503)
			return
		}
		digest := sha256.Sum256([]byte(token))
		grant, err := p.meter.Resolve(r.Context(), &meterpb.ResolveRequest{Owner: session.event.Owner, Endpoint: tunnelID, TokenSha256: digest[:]})
		if err != nil {
			session.reason = "meter_unavailable"
			http.Error(w, "Usage ledger unavailable", 503)
			return
		}
		if strings.HasPrefix(token, "tunn_mcp_") {
			session.event.AuthMethod = "mcp_oauth"
			if grant.Id != "" {
				session.event.Caller = "grant:" + grant.Id
				session.event.GrantId = grant.Id
			}
			if grant.Id == "" || !strings.HasPrefix(grant.Consumer, "oauth:") || grant.Revoked || grant.ExpiresAt <= time.Now().UnixMilli() || r.URL.Path != "/mcp" || tunnel.TargetURL != "mcp" || common.IsWebSocketUpgrade(r.Header) {
				session.reason = "invalid_oauth_token"
				p.mcpChallenge(w, tunnelID, "invalid_token")
				http.Error(w, "Invalid or expired MCP access token", http.StatusUnauthorized)
				return
			}
		}
		if grant.Id == "" || tunnel.EndpointProtocol == "tcp" || common.IsWebSocketUpgrade(r.Header) {
			session.reason = "invalid_grant"
			w.Header().Set("Tunn-Limit-Reason", session.reason)
			http.Error(w, "Invalid endpoint grant", 403)
			return
		}
		session.event.Caller = "grant:" + grant.Id
		session.event.GrantId = grant.Id
		session.event.AuthMethod = "grant"
		if strings.HasPrefix(token, "tunn_mcp_") {
			session.event.AuthMethod = "mcp_oauth"
		}
		grantAuthenticated = true
		r = strippedAuth(r, header)
	}

	common.LogDebug("proxying web request locally",
		"tunnel_id", tunnelID,
		"target", tunnel.TargetURL,
		"path", r.URL.Path,
		"method", r.Method)

	// Auth is only required if the tunnel has an allow-list (--allow was specified)
	// If no allow-list, the tunnel is open to the internet (URLs are random, act like strong passwords)
	if (len(tunnel.AllowedEmails) > 0 || len(tunnel.accessTokenDigest()) > 0) && !grantAuthenticated {
		// Browsers authenticate with the platform cookie. Agents and other
		// machine clients may use a signed tunn token in a bearer header.
		userEmail, platformAuthHeader, capabilityAuthenticated, authenticated := p.getAuthFromTunnelBearer(r, tunnel)
		if !authenticated {
			userEmail, authenticated = p.getAuthFromCookie(r)
		}
		if !authenticated {
			session.reason = "authentication_required"
			// MCP clients cannot consume the browser login redirect. Return an
			// explicit bearer challenge for protocol endpoints and bearer attempts.
			if r.Context().Value(domainOwnerKey{}) != nil || common.IsWebSocketUpgrade(r.Header) || r.URL.Path == "/mcp" || tunnel.EndpointProtocol == "tcp" || r.Header.Get("Authorization") != "" || r.Header.Get("Tunn-Authorization") != "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="tunn"`)
				if r.URL.Path == "/mcp" {
					p.mcpChallenge(w, tunnelID, "")
				}
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Build full return URL including the tunnel subdomain
			returnTo := fmt.Sprintf("https://%s%s", r.Host, r.URL.RequestURI())
			loginURL := fmt.Sprintf("https://%s/auth/login?return_to=%s&tunnel=%s",
				p.config.Domain, url.QueryEscape(returnTo), url.QueryEscape(tunnelID))

			common.LogInfo("unauthenticated tunnel access, redirecting to login",
				"tunnel_id", tunnelID,
				"request_id", session.event.RequestId)
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		session.event.Caller = metering.CallerEmail(common.NormalizeEmail(userEmail))
		session.event.AuthMethod = "cookie"
		if platformAuthHeader != "" {
			session.event.AuthMethod = "jwt"
		}
		if capabilityAuthenticated {
			session.event.Caller = metering.TokenID(tunnel.accessTokenDigest())
			session.event.AuthMethod = "endpoint_token"
		}
		// User is authenticated, check allow-list
		common.LogDebug("authenticated tunnel access",
			"email", userEmail,
			"tunnel_id", tunnelID,
			"path", r.URL.Path)

		userEmails := []string{userEmail}
		allowed := capabilityAuthenticated
		if !capabilityAuthenticated {
			// Get user's email bucket (all emails associated with their account)
			if p.storage != nil && p.storage.Available() {
				if bucket, err := p.storage.GetEmailBucket(r.Context(), userEmail); err == nil {
					userEmails = bucket
				}
			}

			// Check if any email in user's bucket is on the tunnel's allow-list.
			// Creator is implicitly always allowed.
			allowListWithCreator := append(append([]string(nil), tunnel.AllowedEmails...), tunnel.CreatorEmail)
			allowed = isEmailBucketAllowed(userEmails, allowListWithCreator)
		}

		if !allowed {
			session.reason = "allowlist_denied"
			common.LogInfo("access denied - user not on allow-list",
				"email", userEmail,
				"bucket", userEmails,
				"tunnel_id", tunnelID,
				"allowed_emails", tunnel.AllowedEmails)

			if r.URL.Path == "/mcp" || tunnel.EndpointProtocol == "tcp" || platformAuthHeader != "" {
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			writePageStart(w, "tunn - Access Denied")
			_, _ = fmt.Fprintf(w, `<h1 class="error-title">Access denied</h1>
<p>You (<code>%s</code>) are not authorized to access this tunnel.</p>
<p>Contact the tunnel owner to request access.</p>
`, html.EscapeString(userEmail))
			writePageEnd(w)
			return
		}

		common.LogDebug("allow-list check passed",
			"email", userEmail,
			"tunnel_id", tunnelID)

		if platformAuthHeader != "" {
			// Never expose a tunn account credential to the tunneled process. Clone
			// the request so other handlers retain the original headers.
			clonedRequest := r.Clone(r.Context())
			clonedRequest.Header = r.Header.Clone()
			if capabilityAuthenticated {
				parts := strings.Fields(r.Header.Get(platformAuthHeader))
				digest := sha256.Sum256([]byte(parts[1]))
				clonedRequest = clonedRequest.WithContext(context.WithValue(r.Context(), webSocketAccessKey{}, digest[:]))
			}
			clonedRequest = strippedAuth(clonedRequest, platformAuthHeader)
			clonedRequest.Header.Del("Tunn-Authorization")
			// Clients can send both bearer fields. Consume any second tunn
			// credential too, while retaining an unrelated upstream credential.
			if _, otherHeader, _, valid := p.getAuthFromTunnelBearer(clonedRequest, tunnel); valid {
				clonedRequest = strippedAuth(clonedRequest, otherHeader)
			}
			r = clonedRequest
		}
	} else if !grantAuthenticated {
		// Attribute authenticated public traffic without requiring application bearer
		// credentials to be tunn credentials.
		email, header, capability, ok := p.getAuthFromTunnelBearer(r, tunnel)
		if ok {
			session.event.Caller = metering.CallerEmail(common.NormalizeEmail(email))
			session.event.AuthMethod = "jwt"
			if capability {
				session.event.Caller = metering.TokenID(tunnel.accessTokenDigest())
				session.event.AuthMethod = "endpoint_token"
			}
			r = strippedAuth(r, header)
		} else if email, ok := p.getAuthFromCookie(r); ok {
			session.event.Caller = metering.CallerEmail(common.NormalizeEmail(email))
			session.event.AuthMethod = "cookie"
		}
		common.LogDebug("open tunnel - no allow-list", "tunnel_id", tunnelID)
		if r.Header.Get("Tunn-Authorization") != "" {
			clonedRequest := r.Clone(r.Context())
			clonedRequest.Header = r.Header.Clone()
			clonedRequest.Header.Del("Tunn-Authorization")
			r = clonedRequest
		}
	}
	// Check quota before proxying
	if !tunnel.accountQuotaExempt && (tunnel.CreatorEmail != "" || tunnel.AccountID != "") {
		if accountErr == nil && account != nil && account.OperationalState == "" {
			session.reason = "account_unavailable"
			http.Error(w, "Account status unavailable", 503)
			return
		}
		if accountErr != nil || account == nil || !p.planMeter && !p.checkQuota(r.Context(), account.ID, account.Plan) {
			session.reason = "account_quota"
			common.LogInfo("quota exceeded, rejecting request",
				"tunnel_id", tunnelID,
				"creator", tunnel.CreatorEmail,
				"registration_plan", tunnel.Plan)
			http.Error(w, "Quota exceeded - tunnel owner's monthly limit reached", http.StatusTooManyRequests)
			return
		}
	}

	if !session.admit(r.Context(), w, r) {
		return
	}
	r, stopAccountWatch := p.watchAccountRequest(r, tunnel, account)
	defer stopAccountWatch()
	if p.meter != nil {
		ctx, cancel := context.WithCancelCause(r.Context())
		defer cancel(nil)
		r = r.WithContext(ctx)
		go session.watch(ctx, cancel)
	}
	r = r.WithContext(context.WithValue(r.Context(), meterContextKey{}, session))
	if p.meter != nil {
		r.Body = &meterRequestBody{ReadCloser: r.Body, meter: session, ctx: r.Context()}
	}
	meterWriter.bodyMeter = p.meter != nil
	defer func() { _ = r.Body.Close() }()
	var proxyErr error
	if tunnel.EndpointProtocol == "tcp" {
		validPath := r.URL.Path == "" || r.URL.Path == common.TCPConnectPath
		if r.Method != http.MethodConnect || !validPath || r.Header.Get(common.TCPConnectHeader) != common.TCPConnectValue {
			w.Header().Set("Allow", http.MethodConnect)
			meterWriter.bodyMeter = false
			session.reason = "protocol_mismatch"
			http.Error(w, "TCP endpoints require tunn connect", http.StatusMethodNotAllowed)
			return
		}
		proxyErr = p.proxyTCPOverGRPC(w, r, tunnel)
	} else {
		proxyErr = p.proxyHTTPOverGRPC(w, r, tunnel)
	}

	if proxyErr != nil {
		if cause := context.Cause(r.Context()); cause != nil && cause != context.Canceled && cause != context.DeadlineExceeded {
			proxyErr = &responseStartedError{cause}
			if !meterWriter.started {
				proxyErr = cause
			}
		}
		var limit *ingressLimitError
		if errors.As(proxyErr, &limit) {
			w.Header().Set("Tunn-Limit-Reason", limit.decision.Reason)
		}
		var unavailable *meterUnavailableError
		if errors.As(proxyErr, &unavailable) {
			w.Header().Set("Tunn-Limit-Reason", "meter_unavailable")
		}
		meterWriter.bodyMeter = false
		session.recordError(proxyErr, r.Context())
		common.LogError("failed to proxy request", "error", proxyErr, "tunnel_id", tunnelID)
		var truncated *truncatedHTTPResponseError
		if responseHasStarted(proxyErr) && errors.As(proxyErr, &truncated) {
			panic(http.ErrAbortHandler)
		}
		if !responseHasStarted(proxyErr) {
			writeIngressError(w, proxyErr)
		}
		return
	}
}

// Abort the downstream HTTP stream after a failed terminal contract. Returning
// normally would turn an unknown-length partial body into a successful EOF.
type truncatedHTTPResponseError struct{ err error }

func (e *truncatedHTTPResponseError) Error() string { return e.err.Error() }
func (e *truncatedHTTPResponseError) Unwrap() error { return e.err }
func truncatedHTTPResponse(err error) error         { return &truncatedHTTPResponseError{err: err} }

type responseStartedError struct {
	err error
}

func (e *responseStartedError) Error() string { return e.err.Error() }
func (e *responseStartedError) Unwrap() error { return e.err }

func responseHasStarted(err error) bool {
	var started *responseStartedError
	return errors.As(err, &started)
}

// proxyHTTPOverGRPC forwards an HTTP request over the gRPC tunnel and writes the response
func (p *ProxyServer) proxyHTTPOverGRPC(w http.ResponseWriter, r *http.Request, tunnel *TunnelConnection) error {
	if common.IsWebSocketUpgrade(r.Header) {
		if !common.ValidWebSocketRequest(r) {
			http.Error(w, "Invalid WebSocket upgrade; use HTTP/1.1 and version 13", http.StatusBadRequest)
			return nil
		}
		if !tunnel.Supports(common.CapabilityWebSocketV1) {
			http.Error(w, "Publisher does not support WebSockets; upgrade tunn", http.StatusNotImplemented)
			return nil
		}
		return p.proxyWebSocketOverGRPC(w, r, tunnel)
	}
	if tunnel.Supports(common.CapabilityHTTPStreamV1) {
		return p.proxyStreamingHTTPOverGRPC(w, r, tunnel)
	}

	// Generate unique connection ID
	connectionID, err := requestConnectionID(r)
	if err != nil {
		return fmt.Errorf("failed to generate connection ID: %w", err)
	}

	// Read request body with size limit to prevent memory exhaustion
	// Read one extra byte to detect if body exceeds limit
	limitedBody, err := io.ReadAll(io.LimitReader(r.Body, MaxBodySize+1))
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	defer func() { _ = r.Body.Close() }()
	if int64(len(limitedBody)) > MaxBodySize {
		return fmt.Errorf("request body too large (max %d bytes)", MaxBodySize)
	}
	body := limitedBody

	// Convert headers to map (join multi-value headers per HTTP spec)
	// SECURITY: Strip platform cookies to prevent tunnel owners from stealing sessions
	headers := p.forwardedHTTPHeaders(r)

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

	if s := meterForRequest(r); s != nil {
		s.event.Forwarded = true
	}
	common.LogDebug("sent http request to client",
		"connection_id", connectionID,
		"method", r.Method,
		"path", r.URL.Path)

	// Wait for response with timeout
	timeout := 30 * time.Second
	select {
	case httpResp := <-respChan:
		if httpResp.StatusCode < 200 || httpResp.StatusCode > 599 {
			return fmt.Errorf("local target returned invalid final HTTP status %d", httpResp.StatusCode)
		}
		if err := validateResponseTrailers(tunnel, httpResp.TrailerNames, httpResp.Trailers); err != nil {
			return err
		}
		// Check bandwidth rate limit (request + response)
		totalSize := len(body) + len(httpResp.Body)
		if !tunnel.CheckRateLimit(totalSize) {
			common.LogInfo("bandwidth rate limit exceeded",
				"connection_id", connectionID,
				"tunnel_id", tunnel.TunnelID,
				"bytes", totalSize)
			if meterForRequest(r) != nil {
				return &ingressLimitError{decision: &meterpb.Decision{Reason: "bandwidth_rate", Status: 429, RequestsRemaining: -1, BytesRemaining: -1, RetryAfter: 1}}
			}
			http.Error(w, "Bandwidth rate limit exceeded", http.StatusTooManyRequests)
			return nil // Return nil - we handled the error by sending 429
		}

		if err := checkMeteredResponse(r, int64(len(httpResp.Body))); err != nil {
			return err
		}
		// Reserve the buffered response atomically before committing its
		// headers. A preflight alone races other account traffic.
		if writer, ok := w.(*meterResponseWriter); ok && writer.bodyMeter {
			if _, err := writer.meter.charge(r.Context(), false, len(httpResp.Body)); err != nil {
				return err
			}
			writer.bodyMeter = false
		}
		// Write response headers
		copyApplicationResponseHeaderFields(w.Header(), httpResp.Headers, httpResp.HeaderFields)
		if common.HTTPResponseHasBody(r.Method, int(httpResp.StatusCode)) {
			declareResponseTrailers(w.Header(), httpResp.TrailerNames)
		}

		// Write status code
		w.WriteHeader(int(httpResp.StatusCode))

		// Write body
		var n int
		var writeErr error
		if common.HTTPResponseHasBody(r.Method, int(httpResp.StatusCode)) {
			n, writeErr = w.Write(httpResp.Body)
		}
		if meterForRequest(r) != nil {
			recordMeteredWrite(r, n)
		}
		if writeErr != nil {
			return &responseStartedError{err: fmt.Errorf("failed to write response body: %w", writeErr)}
		}

		if common.HTTPResponseHasBody(r.Method, int(httpResp.StatusCode)) {
			writeResponseTrailers(w.Header(), httpResp.Trailers)
		}

		common.LogDebug("proxied http response",
			"connection_id", connectionID,
			"status", httpResp.StatusCode,
			"body_size", len(httpResp.Body))

		// Record usage (request body + response body) using account ID
		if tunnel.AccountID != "" && meterForRequest(r) == nil {
			p.RecordUsage(r.Context(), tunnel.AccountID, int64(totalSize))
		}

		return nil

	case <-r.Context().Done():
		return r.Context().Err()
	case <-tunnel.Stream.Context().Done():
		return fmt.Errorf("tunnel disconnected before buffered response")
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for response after %v", timeout)
	}
}

func (p *ProxyServer) forwardedRequestHeaders(source http.Header) map[string]string {
	headers := make(map[string]string, len(source))
	for key, values := range source {
		// This header belongs exclusively to the relay, even when a browser
		// cookie authenticated the request instead of the bearer credential.
		if strings.EqualFold(key, "Tunn-Authorization") {
			continue
		}
		if strings.EqualFold(key, "Authorization") {
			kept := make([]string, 0, len(values))
			for _, value := range values {
				if !p.isPlatformAuthorization(value) {
					kept = append(kept, value)
				}
			}
			if len(kept) == 0 {
				continue
			}
			values = kept
		}
		value := strings.Join(values, ", ")
		if strings.EqualFold(key, "Cookie") {
			value = stripPlatformCookies(strings.Join(values, "; "))
			if value == "" {
				continue
			}
		}
		headers[key] = value
	}
	return headers
}

// generateConnectionID creates a random connection ID
func generateConnectionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// proxyToNode handles proxying a request to another node in the cluster.
// If the remote node returns 503, the cache entry is invalidated so the next
// request will re-probe for the tunnel's current location.
func (p *ProxyServer) proxyToNode(w http.ResponseWriter, r *http.Request, nodeAddr string, tunnelID string) {
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
	peer, proto := p.forwardingPeer(r)
	proxy.Director = func(req *http.Request) {
		originalHost := req.Host // Save original before Director modifies it
		originalDirector(req)
		req.Host = originalHost // Restore original Host
		req.Header.Del(relayForwardedFor)
		req.Header.Del(relayForwardedProto)
		req.Header.Del(relayForwardedSignature)
		if signature := p.forwardingSignature(originalHost, peer, proto); signature != "" {
			req.Header.Set(relayForwardedFor, peer)
			req.Header.Set(relayForwardedProto, proto)
			req.Header.Set(relayForwardedSignature, signature)
		}
	}

	// Invalidate cache on 503 (tunnel no longer on this node)
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode == http.StatusServiceUnavailable {
			common.LogInfo("remote node returned 503, invalidating cache", "tunnel_id", tunnelID, "node_addr", nodeAddr)
			p.cacheMu.Lock()
			delete(p.tunnelCache, tunnelID)
			p.cacheMu.Unlock()
		}
		return nil
	}

	// We need to create a custom transport to skip TLS verification if needed,
	// since we are using self-signed certs in development.
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: p.config.Insecure},
	}

	common.LogInfo("proxying to remote node", "node_addr", nodeAddr, "tunnel_id", tunnelID)
	proxy.ServeHTTP(w, r)
}

// isLikelyBot checks if a User-Agent looks like a bot/crawler/scanner
func isLikelyBot(ua string) bool {
	ua = strings.ToLower(ua)
	if ua == "" {
		return true
	}
	botPatterns := []string{
		"bot", "crawler", "spider", "scan", "python", "wget", "fetch",
		"http", "axios", "node", "go-http", "java", "ruby", "perl",
		"check", "monitor", "probe", "test", "uptime", "health",
	}
	for _, pattern := range botPatterns {
		if strings.Contains(ua, pattern) {
			return true
		}
	}
	return false
}

// handleApexDomain handles requests to the apex domain (e.g., tunn.to)
func (p *ProxyServer) handleApexDomain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	switch r.URL.Path {
	case "/privacy":
		_, _ = fmt.Fprint(w, privacyHTML)
	case "/terms":
		_, _ = fmt.Fprint(w, termsHTML)
	case "/favicon.ico", "/robots.txt", "/sitemap.xml":
		http.NotFound(w, r)
	default:
		// Only log actual homepage visits, not random path probes
		if r.URL.Path == "/" {
			ua := r.Header.Get("User-Agent")
			ip := extractClientIP(r)
			if isLikelyBot(ua) {
				common.LogInfo("homepage bot", "ip", ip, "ua", ua)
			} else {
				common.LogInfo("homepage human", "ip", ip, "ua", ua)
			}
		}
		_, _ = fmt.Fprint(w, homepageHTML)
	}
}

// isEmailAllowed checks if an email is on the allow-list
// Supports both exact matches ("alice@example.com") and domain wildcards ("@example.com")
// Uses Unicode NFKC normalization to prevent homograph attacks
func isEmailAllowed(email string, allowList []string) bool {
	normalizedEmail := common.NormalizeEmail(email)
	for _, allowed := range allowList {
		normalizedAllowed := common.NormalizeEmail(allowed)
		if strings.HasPrefix(normalizedAllowed, "@") {
			// Domain wildcard: check if email ends with this domain
			if strings.HasSuffix(normalizedEmail, normalizedAllowed) {
				return true
			}
		} else {
			// Exact match
			if normalizedEmail == normalizedAllowed {
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
