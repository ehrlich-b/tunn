package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/inspection"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/webhook"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// MaxBodySize is the maximum HTTP request body size (100 MiB).
// Prevents memory exhaustion from large requests.
const MaxBodySize = 100 * 1024 * 1024

type domainAppKey struct{}

type requestBodyTooLargeError struct{ limit int64 }

func (e *requestBodyTooLargeError) Error() string {
	return fmt.Sprintf("Request body too large: upload limit is %d bytes (100 MiB)", e.limit)
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
	r = stripIdentityHeaders(r)
	// Extract tunnel ID from hostname
	tunnelID := extractTunnelID(requestHostname(r.Host), p.Domain)
	if p.customerHost(r.Host) {
		admission, stop := context.WithDeadline(r.Context(), p.appAdmissionDeadline(r))
		defer stop()
		r = r.WithContext(context.WithValue(r.Context(), appAdmissionKey{}, admission))
		if !p.prepareAppCredential(w, r, admission) {
			return
		}
		if p.domains == nil {
			http.NotFound(w, r)
			return
		}
		binding, err := p.domains.Route(admission, &domainpb.Domain{Name: requestHostname(r.Host)})
		if err != nil {
			p.appRouteFailure(w, r, err)
			return
		}
		tunnelID = binding.Tunnel
		if strings.HasPrefix(binding.Name, "*.") {
			r = r.WithContext(context.WithValue(r.Context(), domainAppKey{}, true))
		}
		r = r.WithContext(context.WithValue(r.Context(), domainOwnerKey{}, binding.Owner))
	}

	// If this is the apex domain (no tunnel ID), show info page
	if tunnelID == "" {
		p.handleApexDomain(w, r)
		return
	}
	if isAppCredentialAttempt(r) && r.Context().Value(domainAppKey{}) != true {
		appAuthenticationError(w, 401)
		return
	}
	// 1. Check if tunnel is local
	if _, exists := p.tunnelServer.GetTunnel(tunnelID); exists {
		err := p.proxyToLocal(w, r, tunnelID)
		var truncated *truncatedHTTPResponseError
		if responseHasStarted(err) && errors.As(err, &truncated) {
			// Only the net/http boundary may abort the downstream stream.
			// A normal return would turn an unknown-length partial body into EOF.
			panic(http.ErrAbortHandler)
		}
		return
	}
	// A replay is pinned to the publisher that supplied the selected history.
	// Never migrate it to another connection or node after preparation.
	if _, replay := r.Context().Value(inspectorReplayKey{}).(*inspectorReplay); replay {
		http.Error(w, "Endpoint reconnected; prepare a new replay", http.StatusConflict)
		return
	}
	// Reject a known oversized upload before probing or forwarding to another
	// node. Local requests also retain their authentication and admission audit.
	if r.Method != http.MethodConnect && r.ContentLength > MaxBodySize {
		writeIngressError(w, &requestBodyTooLargeError{MaxBodySize})
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
		probeParent := r.Context()
		if admission, _ := r.Context().Value(appAdmissionKey{}).(context.Context); admission != nil {
			probeParent = admission
		}
		probeCtx, cancel := context.WithTimeout(probeParent, 5*time.Second)
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
			auditContext, stopAudit := appAuthorityContext(r)
			_, err = p.meter.Admit(auditContext, &meterpb.Event{RequestId: id, Endpoint: tunnelID, Caller: "anonymous", AuthMethod: "none", Reason: "endpoint_offline", Status: 503})
			stopAudit()
			if err != nil {
				p.operations.drops.Add(1)
				common.LogError("failed to audit offline endpoint", "request_id", id, "error", err)
			}
		}
	}
	http.Error(w, "Tunnel not found or offline", http.StatusServiceUnavailable)
}

// proxyToLocal writes the response for a tunnel hosted on the current node and
// returns forwarding errors after recording them. Errors before response headers
// receive an HTTP error response; started, truncated responses require the HTTP
// caller to abort its stream. Direct callers can inspect errors without a panic.
func (p *ProxyServer) proxyToLocal(w http.ResponseWriter, r *http.Request, tunnelID string) error {
	w = protectResponse(w)
	tunnel, exists := p.tunnelServer.GetTunnel(tunnelID)
	if !exists {
		http.Error(w, "Tunnel offline", http.StatusServiceUnavailable)
		return nil
	}
	r = stripIdentityHeaders(r)
	// Verification and replay reconstruction use inputs before owner header edits.
	incomingHeaders := r.Header.Clone()
	replay, isReplay := r.Context().Value(inspectorReplayKey{}).(*inspectorReplay)
	if isReplay && replay.tunnel != tunnel {
		http.Error(w, "Endpoint reconnected; prepare a new replay", http.StatusConflict)
		return nil
	}
	if expected, ok := r.Context().Value(sshConnectTunnelKey{}).(*TunnelConnection); ok && expected != tunnel {
		http.Error(w, "SSH endpoint replaced", http.StatusForbidden)
		return nil
	}
	accountContext, stopAccountLookup := appAuthorityContext(r)
	if r.Context().Value(domainAppKey{}) == true && r.Context().Value(appPrecheckedKey{}) == nil {
		if !p.prepareAppCredential(w, r, accountContext) {
			stopAccountLookup()
			return nil
		}
	}
	account, accountErr := p.currentTunnelAccount(accountContext, tunnel)
	stopAccountLookup()
	if r.Context().Value(domainAppKey{}) == true && accountErr != nil {
		code := 503
		if errors.Is(accountErr, errUnknownTunnelAccount) {
			code = 403
		}
		http.Error(w, http.StatusText(code), code)
		return nil
	}
	if isReplay && (accountErr != nil || account == nil || account.ID != replay.owner || account.OperationalState != "active") {
		http.Error(w, "Active endpoint owner required", http.StatusForbidden)
		return nil
	}
	if owner, ok := r.Context().Value(domainOwnerKey{}).(string); ok && (owner == "" || account == nil || account.ID != owner) {
		http.Error(w, "Domain tunnel ownership mismatch", http.StatusForbidden)
		return nil
	}

	probe, _ := r.Context().Value(forwardPermissionProbeKey{}).(*bool)
	var session *ingressMeter
	if probe != nil {
		id, _ := generateConnectionID()
		session = &ingressMeter{proxy: p, accountID: tunnel.AccountID, event: &meterpb.Event{RequestId: id, Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Caller: "anonymous", AuthMethod: "none", Allowed: true, Reason: "allowed", StartedAt: time.Now().UnixMilli()}}
	} else {
		session = newIngressMeter(p, tunnel)
	}
	if account != nil {
		session.accountID, session.event.Owner = account.ID, account.ID
		tunnel.updateBandwidthPlan(account.Plan)
	}
	meterWriter := &meterResponseWriter{ResponseWriter: w, meter: session, ctx: r.Context(), status: 200}
	w = meterWriter
	if p.meter != nil {
		w.Header().Set("Tunn-Request-ID", session.event.RequestId)
	}
	defer func() {
		if probe != nil && !*probe && r.Context().Value(forwardPermissionAdmissionKey{}) == true {
			session.backend = p.meter
			if meterWriter.status >= 400 || session.reason == "authentication_required" {
				p.operations.denied.Add(1)
			}
		}
		session.complete(r.Context(), meterWriter)
	}()
	if tunnel.AccountID != "" && p.ipPolicyBackend() != nil && (accountErr != nil || account == nil) {
		http.Error(w, "IP policy ownership authority unavailable", 503)
		return nil
	}
	owner := tunnel.AccountID
	if account != nil {
		owner = account.ID
	}
	if (probe == nil || r.Context().Value(forwardPermissionAdmissionKey{}) == true) && !p.checkOwnerIPPolicy(w, r, owner, tunnelID) {
		session.reason = "ip_policy_denied"
		if meterWriter.status == 503 {
			session.reason = "ip_policy_authority_unavailable"
		}
		return nil
	}

	appEmail, appOwner := "", false
	if r.Context().Value(domainAppKey{}) == true {
		appSession, allowed := p.authorizeDomainApp(w, r, account, tunnel)
		if !allowed {
			return nil
		}
		defer p.releaseAppDevice(r)
		appEmail, _ = appSession["email"].(string)
		appID, _ := appSession["account_id"].(string)
		appProvider, _ := appSession["provider"].(string)
		appOwner = account != nil && appID == account.ID
		assertion, err := "", error(nil)
		if r.Context().Value(forwardPermissionProbeKey{}) == nil {
			assertion, err = p.appAssertion(requestHostname(r.Host), appID, appEmail, appProvider)
		}
		if err != nil {
			http.Error(w, "Identity signer unavailable", 503)
			return nil
		}
		r.Header.Set("X-Tunn-Identity", assertion)
		r.Header.Set("X-Tunn-User-Email", appEmail)
	}
	admissionContext := r.Context()
	if r.Context().Value(domainAppKey{}) == true {
		admissionContext, _ = appAuthorityContext(r)

	}
	grantAuthenticated := false
	var webResource *meterpb.WebResource
	var webEmails []string
	var orgIdentity *orgSession
	if tunnel.ResourceID != "" {
		var err error
		webResource, err = p.webResource(admissionContext, tunnel)
		if err != nil {
			session.reason = "permission_authority_unavailable"
			http.Error(w, "Web permission authority unavailable", 503)
			return nil
		}
	}

	// A known suspension rejects every credential path. Unresolved ownership
	// still follows authentication and the existing fail-closed quota check.
	if !tunnel.accountQuotaExempt && accountErr == nil && account != nil && account.OperationalState != "" && account.OperationalState != "active" {
		session.reason = "account_suspended"
		w.Header().Set("Tunn-Limit-Reason", session.reason)
		http.Error(w, session.reason, http.StatusForbidden)
		return nil
	}
	if token, header := grantBearer(r); token != "" {
		if p.meter == nil {
			session.reason = "meter_unavailable"
			http.Error(w, "Usage ledger unavailable", http.StatusServiceUnavailable)
			return nil
		}
		digest := sha256.Sum256([]byte(token))
		grant, err := p.meter.Resolve(r.Context(), &meterpb.ResolveRequest{Owner: session.event.Owner, Endpoint: tunnelID, TokenSha256: digest[:]})
		if err != nil {
			session.reason = "meter_unavailable"
			http.Error(w, "Usage ledger unavailable", http.StatusServiceUnavailable)
			return nil
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
				return nil
			}
		}
		if grant.Id == "" || tunnel.EndpointProtocol == "tcp" || common.IsWebSocketUpgrade(r.Header) {
			session.reason = "invalid_grant"
			w.Header().Set("Tunn-Limit-Reason", session.reason)
			http.Error(w, "Invalid endpoint grant", http.StatusForbidden)
			return nil
		}
		session.event.Caller = "grant:" + grant.Id
		session.event.GrantId = grant.Id
		session.event.AuthMethod = "grant"
		if grant.Revoked || grant.ExpiresAt <= time.Now().UnixMilli() {
			session.reason = "grant_expired"
			if grant.Revoked {
				session.reason = "grant_revoked"
			}
			w.Header().Set("Tunn-Limit-Reason", session.reason)
			http.Error(w, "Invalid endpoint grant", http.StatusForbidden)
			return nil
		}
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

	// Modern web admission uses live permissions, including an empty owner-only list.
	if (webResource != nil && webResource.Mode == "private" || len(tunnel.AllowedEmails) > 0 || len(tunnel.accessTokenDigest()) > 0) && !grantAuthenticated {
		// Browsers authenticate with the platform cookie. Agents and other
		// machine clients may use a signed tunn token in a bearer header.
		userEmail, platformAuthHeader, capabilityAuthenticated, authenticated := p.getAuthFromTunnelBearer(r, tunnel)
		if appEmail != "" {
			userEmail, platformAuthHeader, capabilityAuthenticated, authenticated = appEmail, "", false, true
		}
		if isReplay {
			userEmail, platformAuthHeader, capabilityAuthenticated, authenticated = account.PrimaryEmail, "", false, true
			appOwner = true
		}
		if !authenticated {
			userEmail, authenticated = p.getAuthFromCookie(r)
			if authenticated {
				orgIdentity, _ = p.getOrgSession(r)
			}
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
				return nil
			}

			// Build full return URL including the tunnel subdomain
			returnTo := fmt.Sprintf("https://%s%s", r.Host, r.URL.RequestURI())
			loginURL := fmt.Sprintf("https://%s/auth/login?return_to=%s&tunnel=%s",
				p.loginAuthority(), url.QueryEscape(returnTo), url.QueryEscape(tunnelID))

			common.LogInfo("unauthenticated tunnel access, redirecting to login",
				"tunnel_id", tunnelID,
				"request_id", session.event.RequestId)
			http.Redirect(w, r, loginURL, http.StatusFound)
			return nil
		}

		session.event.Caller = metering.CallerEmail(common.NormalizeEmail(userEmail))
		session.event.AuthMethod = "cookie"
		if platformAuthHeader != "" {
			session.event.AuthMethod = "jwt"
		}
		if orgIdentity != nil {
			session.event.AuthMethod = "org_oidc"
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
		allowed := capabilityAuthenticated || appOwner
		if !capabilityAuthenticated && !appOwner {
			// Get user's email bucket (all emails associated with their account)
			if orgIdentity == nil && p.storage != nil && p.storage.Available() {
				if bucket, err := p.storage.GetEmailBucket(admissionContext, userEmail); err == nil {
					userEmails = bucket
				} else if r.Context().Value(domainAppKey{}) == true {
					http.Error(w, "Account authority unavailable", 503)
					return nil
				}
			}

			// Check if any email in user's bucket is on the tunnel's allow-list.
			// Creator is implicitly always allowed.
			allowListWithCreator := append(append([]string(nil), tunnel.AllowedEmails...), tunnel.CreatorEmail)
			if webResource != nil {
				webEmails = append([]string(nil), userEmails...)
				var groups []string
				if orgIdentity != nil {
					groups = orgIdentity.Groups
				}
				allowed = webIdentityAllowed(webResource, userEmails, groups, tunnel.CreatorEmail, p.currentTime())
			} else {
				allowed = isEmailBucketAllowed(userEmails, allowListWithCreator)
			}
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
				return nil
			}

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			writePageStart(w, "tunn - Access Denied")
			_, _ = fmt.Fprintf(w, `<h1 class="error-title">Access denied</h1>
<p>You (<code>%s</code>) are not authorized to access this tunnel.</p>
<p>Contact the tunnel owner to request access.</p>
`, html.EscapeString(userEmail))
			writePageEnd(w)
			return nil
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
	if isReplay {
		session.event.Caller = metering.CallerEmail(common.NormalizeEmail(account.PrimaryEmail))
		session.event.AuthMethod = "inspector_replay"
	}
	if probe == nil && r.Context().Value(domainAppKey{}) == true {

		var stop func()
		r, stop = p.watchAppPermission(r, tunnel)
		defer stop()
	} else if probe == nil && webResource != nil {
		var stop func()
		r, stop = p.watchWebPermission(r, tunnel, webEmails, webResource.Mode != "private" && !grantAuthenticated)
		defer stop()
	}
	// Check quota before proxying
	if !tunnel.accountQuotaExempt && (tunnel.CreatorEmail != "" || tunnel.AccountID != "") {
		if accountErr == nil && account != nil && account.OperationalState == "" {
			session.reason = "account_unavailable"
			http.Error(w, "Account status unavailable", http.StatusServiceUnavailable)
			return nil
		}
		if accountErr != nil || account == nil || !p.planMeter && !p.checkQuota(admissionContext, account.ID, account.Plan) {
			if r.Context().Value(domainAppKey{}) == true && admissionContext.Err() != nil {
				http.Error(w, "Account authority unavailable", 503)
				return nil
			}
			session.reason = "account_quota"
			common.LogInfo("quota exceeded, rejecting request",
				"tunnel_id", tunnelID,
				"creator", tunnel.CreatorEmail,
				"registration_plan", tunnel.Plan)
			http.Error(w, "Quota exceeded - tunnel owner's monthly limit reached", http.StatusTooManyRequests)
			return nil
		}
	}

	if probe != nil {
		*probe = true
		return nil
	}

	if tunnel.EndpointProtocol != "tcp" && r.ContentLength > MaxBodySize {
		session.reason = "request_body_too_large"
		session.event.ContentLength = r.ContentLength
		writeIngressError(w, &requestBodyTooLargeError{MaxBodySize})
		return nil
	}
	var policyAllowed bool
	r, policyAllowed = p.applyEndpointPolicy(w, r, tunnel, session)
	if !policyAllowed {
		return nil
	}
	if !session.admit(admissionContext, w, r) {
		return nil
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
	meterWriter.ctx = r.Context()
	downstream, stopIO := interruptResponseOnCancellation(meterWriter.ResponseWriter, r)
	meterWriter.ResponseWriter = downstream
	defer stopIO()
	if r.Context().Value(domainAppKey{}) == true {
		controller := http.NewResponseController(w)
		done := make(chan struct{})
		stopAppIO := context.AfterFunc(r.Context(), func() { defer close(done); _ = controller.SetReadDeadline(time.Now()) })
		defer func() {
			if !stopAppIO() {
				<-done
			}
		}()
		p.signalAppAdmission(w, r)
	}
	if p.meter != nil {
		r.Body = &meterRequestBody{ReadCloser: r.Body, meter: session, ctx: r.Context()}
	}
	meterWriter.bodyMeter = p.meter != nil
	defer func() { _ = r.Body.Close() }()
	if tunnel.WebhookPolicy != nil {
		// Authorization and admission precede the bounded read. The metered
		// wrapper charges its bytes once; Verify restores an unmetered copy
		// for origin forwarding rather than charging that copy a second time.
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(webhook.ReadTimeout))
		verificationRequest := r.Clone(r.Context())
		verificationRequest.Header = incomingHeaders
		err := tunnel.WebhookPolicy.Verify(verificationRequest, time.Now)
		r.Body = verificationRequest.Body
		_ = controller.SetReadDeadline(time.Time{})
		if err != nil {
			meterWriter.bodyMeter = false
			if cause := context.Cause(r.Context()); cause != nil {
				session.recordError(cause, r.Context())
				writeIngressError(w, cause)
				return nil
			}
			var limit *ingressLimitError
			var unavailable *meterUnavailableError
			if errors.As(err, &limit) || errors.As(err, &unavailable) || r.Context().Err() != nil {
				session.recordError(err, r.Context())
				writeIngressError(w, err)
				return nil
			}
			session.reason = "webhook_verification_failed"
			http.Error(w, "Webhook verification failed: "+err.Error(), http.StatusUnauthorized)
			return nil
		}
		// A permission/account watcher or the caller may have cancelled while
		// the body was buffered. Never open an origin request after cancellation.
		if cause := context.Cause(r.Context()); cause != nil {
			meterWriter.bodyMeter = false
			session.recordError(cause, r.Context())
			writeIngressError(w, cause)
			return nil
		}
	}
	var proxyErr error
	if tunnel.EndpointProtocol != "tcp" && !common.IsWebSocketUpgrade(r.Header) {
		if history := tunnel.inspectionHistory(); history != nil {
			captureRequest := r.Clone(r.Context())
			captureRequest.Header = incomingHeaders.Clone()
			headers := p.forwardedRequestHeaders(stripIdentityHeaders(captureRequest).Header)
			// These fields are stripped/regenerated by forwardedHTTPHeaders;
			// they are not original application inputs the owner can restore.
			for name := range headers {
				lower := strings.ToLower(name)
				if lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "tunn-relay-") {
					delete(headers, name)
				}
			}
			headers["Host"] = r.Host
			replayOf := uint64(0)
			if isReplay {
				replayOf = replay.originalID
			}
			capture := history.Begin(session.event.RequestId, r.Method, r.URL.RequestURI(), headers, r.ContentLength, replayOf)
			r.Body = &inspection.Body{ReadCloser: r.Body, Capture: capture}
			observed := &inspection.Response{ResponseWriter: meterWriter.ResponseWriter, Capture: capture, Status: http.StatusOK}
			// Keep the metering writer outermost: buffered and streamed adapters
			// use its concrete type to reserve bytes before response commitment.
			meterWriter.ResponseWriter = observed
			defer func() {
				reason := "complete"
				session.mu.Lock()
				failed := session.reason != ""
				session.mu.Unlock()
				if proxyErr != nil || failed {
					reason = "proxy_error"
				}
				if r.Context().Err() != nil {
					reason = "canceled"
				}
				event := capture.Finish(observed.Status, observed.ContentType, reason)
				if isReplay {
					replay.result = event
				}
			}()
		}
	}
	if tunnel.EndpointProtocol == "tcp" {
		validPath := r.URL.Path == "" || r.URL.Path == common.TCPConnectPath
		if r.Method != http.MethodConnect || !validPath || r.Header.Get(common.TCPConnectHeader) != common.TCPConnectValue {
			w.Header().Set("Allow", http.MethodConnect)
			meterWriter.bodyMeter = false
			session.reason = "protocol_mismatch"
			http.Error(w, "TCP endpoints require tunn connect", http.StatusMethodNotAllowed)
			return nil
		}
		proxyErr = p.proxyTCPOverGRPC(w, r, tunnel)
	} else {
		proxyErr = p.proxyHTTPOverGRPC(w, r, tunnel)
	}

	if proxyErr != nil {
		if cause := context.Cause(r.Context()); cause != nil && cause != context.Canceled && cause != context.DeadlineExceeded {
			var truncated *truncatedHTTPResponseError
			if errors.As(proxyErr, &truncated) {
				proxyErr = &responseStartedError{truncatedHTTPResponse(cause)}
			} else {
				proxyErr = &responseStartedError{cause}
			}
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
		if !responseHasStarted(proxyErr) {
			if localAppUnreachable(proxyErr) && acceptsHTML(r) {
				p.writeLocalAppDown(w, r)
			} else {
				writeIngressError(w, proxyErr)
			}
		}
		return proxyErr
	}
	return nil
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
	if r.ContentLength > MaxBodySize {
		return &requestBodyTooLargeError{MaxBodySize}
	}
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
		return &requestBodyTooLargeError{MaxBodySize}
	}
	body := limitedBody

	headers, fields, ok := p.negotiatedRequestHeaders(w, r, tunnel)
	if !ok {
		return nil
	}

	// Create HttpRequest message
	httpReq := &pb.HttpRequest{
		ConnectionId: connectionID,
		Method:       r.Method,
		Path:         r.URL.RequestURI(),
		Headers:      headers,
		HeaderFields: fields,
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

	if err := tunnel.SendMessageContext(r.Context(), msg); err != nil {
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
	headers, _ := common.EncodeHTTPRequestHeaders(p.forwardedApplicationHeaders(source))
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
	var admission *appForwardAdmission
	if r.Context().Value(domainAppKey{}) == true {
		check, stop := appAuthorityContext(r)
		if check.Err() != nil {
			stop()
			http.Error(w, "Admission authority unavailable", 503)
			return
		}
		if p.config.NodeSecret == "" {
			stop()
			http.Error(w, "Relay authentication unavailable", 503)
			return
		}
		d, _ := check.Deadline()
		stop()
		var stopWatch func()
		r, stopWatch = p.watchForwardedApp(r)
		defer stopWatch()
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		id, err := generateConnectionID()
		if err != nil {
			http.Error(w, "Admission unavailable", 503)
			return
		}
		peer, proto := p.forwardingPeer(r)
		admission = &appForwardAdmission{deadline: d, id: id, cancel: cancel}
		admission.proof = p.appRelaySignature(r.Host, peer, proto, strconv.FormatInt(d.UnixMilli(), 10), id, "admitted")
		admission.timer = time.AfterFunc(max(time.Until(d), 0), cancel)
		defer admission.timer.Stop()
		r = r.WithContext(httptrace.WithClientTrace(ctx, admission.trace()))
		writer := &appForwardWriter{ResponseWriter: w, ctx: r.Context()}
		stopIO := context.AfterFunc(r.Context(), writer.abort)
		defer stopIO()
		w = writer
	} else if tunnelID != "" {
		var stop func()
		var allowed bool
		r, w, stop, allowed = p.watchForwardedPermission(w, r, nodeAddr, tunnelID)
		defer stop()
		if !allowed {
			return
		}
	}
	target, err := url.Parse("https://" + nodeAddr)
	if err != nil {
		common.LogError("failed to parse node address", "error", err, "node_addr", nodeAddr)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Preserve endpoint authority, and install signed peer metadata after the
	// proxy removes hop headers named by an untrusted Connection header.
	peer, proto := p.forwardingPeer(r)
	if p.forwardingSignature(r.Host, peer, proto) == "" {
		http.Error(w, "Relay identity unavailable", http.StatusServiceUnavailable)
		return
	}
	proxy.Director = nil
	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		req := pr.Out
		originalHost := pr.In.Host
		req.Host = originalHost
		req.Header.Del(relayForwardedFor)
		req.Header.Del(relayForwardedProto)
		req.Header.Del(relayForwardedSignature)
		req.Header.Del(appRelayDeadline)
		req.Header.Del(appRelayAdmissionID)
		req.Header.Del(appRelayAdmissionSignature)
		if signature := p.forwardingSignature(originalHost, peer, proto); signature != "" {
			req.Header.Set(relayForwardedFor, peer)
			req.Header.Set(relayForwardedProto, proto)
			req.Header.Set(relayForwardedSignature, signature)
		}
		if admission != nil {
			deadline := strconv.FormatInt(admission.deadline.UnixMilli(), 10)
			req.Header.Set(appRelayDeadline, deadline)
			req.Header.Set(appRelayAdmissionID, admission.id)
			req.Header.Set(appRelayAdmissionSignature, p.appRelaySignature(originalHost, peer, proto, deadline, admission.id, "request"))
		}
	}

	// Invalidate cache on 503 (tunnel no longer on this node)
	proxy.ModifyResponse = func(resp *http.Response) error {
		if admission != nil {
			admission.timer.Stop()
		}
		if resp.StatusCode == http.StatusServiceUnavailable {
			common.LogInfo("remote node returned 503, invalidating cache", "tunnel_id", tunnelID, "node_addr", nodeAddr)
			p.cacheMu.Lock()
			delete(p.tunnelCache, tunnelID)
			p.cacheMu.Unlock()
		}
		return nil
	}

	// HTTP and CONNECT use the same configured relay trust roots.
	tlsConfig, err := p.relayTLSConfig()
	if err != nil {
		http.Error(w, "Relay trust unavailable", 503)
		return
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	if admission != nil {
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			dial, stop := context.WithDeadline(ctx, admission.deadline)
			defer stop()
			return (&net.Dialer{}).DialContext(dial, network, address)
		}
		transport.TLSHandshakeTimeout = max(time.Until(admission.deadline), time.Millisecond)
	}
	defer transport.CloseIdleConnections()
	proxy.Transport = transport
	if admission != nil {
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			if writer, ok := w.(*appForwardWriter); ok && !writer.started.Load() {
				http.Error(writer.ResponseWriter, "Relay admission unavailable", 503)
				return
			}
			http.Error(w, "Relay admission or stream unavailable", 503)
		}
	}
	defer proxy.Transport.(*http.Transport).CloseIdleConnections()
	if r.Method == http.MethodConnect {
		p.proxyConnectToNode(w, r, target, peer, proto, tunnelID)
		return
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
	if p.serveDistributionPage(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	switch r.URL.Path {
	case "/privacy":
		_, _ = fmt.Fprint(w, withSiteChrome(privacyHTML))
	case "/terms":
		p.renderRevenuePage(w, termsHTML)
	case "/favicon.ico", "/robots.txt", "/sitemap.xml":
		http.NotFound(w, r)
	case "/":
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
		p.renderRevenuePage(w, homepageHTML)
	default:
		http.NotFound(w, r)
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
