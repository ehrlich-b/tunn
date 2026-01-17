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
		if p.accounts != nil {
			if bucket, err := p.accounts.GetEmailBucket(userEmail); err == nil {
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
	w.WriteHeader(http.StatusOK)

	// Get active tunnel count for the footer
	activeTunnels := p.tunnelServer.GetActiveTunnelCount()

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tunn - share localhost instantly</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  background: #ffffff;
  color: #1f2328;
  line-height: 1.6;
}
code, pre, .mono {
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
}
.container { max-width: 720px; margin: 0 auto; padding: 0 24px; }

/* Hero */
.hero { padding: 80px 0 48px; text-align: center; }
.logo { font-size: 48px; font-weight: 700; color: #0969da; margin-bottom: 32px; }

/* Command showcase */
.command-showcase {
  background: #f6f8fa;
  border: 1px solid #d1d9e0;
  border-radius: 12px;
  padding: 24px 28px;
  margin-bottom: 20px;
  text-align: left;
}
.command-showcase pre {
  font-size: 15px;
  line-height: 1.7;
  margin: 0;
}
.command-showcase .prompt { color: #57606a; }
.command-showcase .cmd { color: #1f2328; }
.command-showcase .output { color: #0969da; }
.command-showcase .comment { color: #57606a; }

.tagline {
  font-size: 18px;
  color: #57606a;
  margin-bottom: 32px;
}

/* Install */
.install-box {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  background: #f6f8fa;
  border: 1px solid #d1d9e0;
  border-radius: 8px;
  padding: 12px 16px;
}
.install-cmd {
  font-size: 14px;
  color: #1f2328;
}
.copy-btn {
  background: #0969da;
  border: none;
  color: white;
  padding: 6px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
}
.copy-btn:hover { background: #0860ca; }
.install-note { color: #57606a; font-size: 13px; margin-top: 12px; }

/* Pricing */
.pricing { padding: 64px 0; }
.pricing h2 { font-size: 28px; font-weight: 600; text-align: center; margin-bottom: 12px; }

.billing-toggle {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 12px;
  margin-bottom: 32px;
  font-size: 14px;
  color: #57606a;
}
.billing-toggle label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}
.billing-toggle input[type="checkbox"] {
  width: 40px;
  height: 22px;
  appearance: none;
  background: #d1d9e0;
  border-radius: 11px;
  position: relative;
  cursor: pointer;
  transition: background 0.2s;
}
.billing-toggle input[type="checkbox"]:checked {
  background: #0969da;
}
.billing-toggle input[type="checkbox"]::before {
  content: '';
  position: absolute;
  width: 18px;
  height: 18px;
  background: white;
  border-radius: 50%%;
  top: 2px;
  left: 2px;
  transition: transform 0.2s;
}
.billing-toggle input[type="checkbox"]:checked::before {
  transform: translateX(18px);
}
.billing-toggle .save { color: #1a7f37; font-weight: 500; }

.pricing-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 20px;
}
.plan {
  background: #ffffff;
  border: 1px solid #d1d9e0;
  border-radius: 12px;
  padding: 28px 24px;
  display: flex;
  flex-direction: column;
}
.plan.featured {
  border: 2px solid #0969da;
  box-shadow: 0 4px 12px rgba(9, 105, 218, 0.15);
}
.plan-name { font-size: 18px; font-weight: 600; margin-bottom: 4px; }
.plan-price {
  font-size: 36px;
  font-weight: 700;
  color: #1f2328;
  margin-bottom: 4px;
}
.plan-price .period { font-size: 16px; font-weight: 400; color: #57606a; }
.plan-period-note { font-size: 13px; color: #57606a; margin-bottom: 20px; min-height: 20px; }
.plan-features { list-style: none; flex: 1; }
.plan-features li {
  padding: 8px 0;
  font-size: 14px;
  color: #1f2328;
  border-bottom: 1px solid #f0f0f0;
}
.plan-features li:last-child { border-bottom: none; }
.plan-features li::before { content: none; }

/* Self-host */
.selfhost {
  padding: 48px 0;
  border-top: 1px solid #d1d9e0;
}
.selfhost h2 { font-size: 20px; font-weight: 600; margin-bottom: 12px; }
.selfhost p { color: #57606a; font-size: 15px; margin-bottom: 16px; }
.selfhost a { color: #0969da; text-decoration: none; }
.selfhost a:hover { text-decoration: underline; }
.code-block {
  background: #f6f8fa;
  border: 1px solid #d1d9e0;
  border-radius: 8px;
  padding: 16px 20px;
  overflow-x: auto;
}
.code-block pre { font-size: 14px; line-height: 1.7; margin: 0; }
.code-block .comment { color: #57606a; }

/* Footer */
.footer {
  padding: 32px 0;
  border-top: 1px solid #d1d9e0;
  text-align: center;
  color: #57606a;
  font-size: 13px;
}
.footer a { color: #0969da; text-decoration: none; }
.footer a:hover { text-decoration: underline; }

@media (max-width: 700px) {
  .hero { padding: 48px 0 32px; }
  .logo { font-size: 36px; }
  .command-showcase { padding: 16px 20px; }
  .command-showcase pre { font-size: 13px; }
  .pricing-grid { grid-template-columns: 1fr; }
  .install-box { flex-direction: column; width: 100%%; }
}
</style>
</head>
<body>

<div class="container">
  <section class="hero">
    <div class="logo">tunn</div>

    <div class="command-showcase">
<pre><span class="prompt">$</span> <span class="cmd">tunn 8080 --allow alice@gmail.com</span>
<span class="output">https://abc123.tunn.to -> localhost:8080</span>
<span class="output">Accessible by: you, alice@gmail.com</span></pre>
    </div>

    <div class="tagline">Share localhost like a Google Doc</div>

    <div class="install-box">
      <code class="install-cmd">curl -fsSL tunn.to/install.sh | sh</code>
      <button class="copy-btn" onclick="navigator.clipboard.writeText('curl -fsSL tunn.to/install.sh | sh')">Copy</button>
    </div>
    <div class="install-note">macOS and Linux. No sudo required.</div>
  </section>

  <section class="pricing">
    <h2>Pricing</h2>

    <div class="billing-toggle">
      <span>Monthly</span>
      <label>
        <input type="checkbox" id="yearly" checked onchange="toggleBilling()">
      </label>
      <span>Yearly <span class="save">(save 20%%)</span></span>
    </div>

    <div class="pricing-grid">
      <div class="plan">
        <div class="plan-name">Free</div>
        <div class="plan-price">$0</div>
        <div class="plan-period-note"></div>
        <ul class="plan-features">
          <li>100 MB / month</li>
          <li>Random subdomains</li>
          <li>Email allow-lists</li>
          <li>Unlimited tunnels</li>
        </ul>
      </div>
      <div class="plan featured">
        <div class="plan-name">Pro</div>
        <div class="plan-price" id="pro-price">$4<span class="period">/mo</span></div>
        <div class="plan-period-note" id="pro-note">Billed yearly ($48/year)</div>
        <ul class="plan-features">
          <li>50 GB / month</li>
          <li>4 reserved *.tunn.to subdomains</li>
          <li>Priority support</li>
          <li>Everything in Free</li>
        </ul>
      </div>
      <div class="plan">
        <div class="plan-name">Enterprise</div>
        <div class="plan-price">Custom</div>
        <div class="plan-period-note"></div>
        <ul class="plan-features">
          <li>Unlimited bandwidth</li>
          <li>Custom domains</li>
          <li>SSO integration</li>
          <li>SLA + dedicated support</li>
        </ul>
      </div>
    </div>
  </section>

  <section class="selfhost">
    <h2>Self-host</h2>
    <p>tunn is open source. Run your own instance on any server.</p>
    <div class="code-block">
<pre><span class="comment"># Install and run as server</span>
curl -fsSL tunn.to/install.sh | sh
tunn -mode=host -domain=tunnel.yourcompany.com</pre>
    </div>
    <p style="margin-top: 16px;">
      <a href="https://github.com/ehrlich-b/tunn">View on GitHub</a>
    </p>
  </section>

  <footer class="footer">
    %d active tunnels &middot; <a href="https://github.com/ehrlich-b/tunn">GitHub</a>
  </footer>
</div>

<script>
function toggleBilling() {
  const yearly = document.getElementById('yearly').checked;
  const price = document.getElementById('pro-price');
  const note = document.getElementById('pro-note');
  if (yearly) {
    price.innerHTML = '$4<span class="period">/mo</span>';
    note.textContent = 'Billed yearly ($48/year)';
  } else {
    price.innerHTML = '$5<span class="period">/mo</span>';
    note.textContent = 'Billed monthly';
  }
}
</script>

</body>
</html>`, activeTunnels)
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
