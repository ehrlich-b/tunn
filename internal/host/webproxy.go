package host

import (
	"fmt"
	"net/http"

	"github.com/ehrlich-b/tunn/internal/common"
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

	// Look up the tunnel connection
	tunnel, exists := p.tunnelServer.GetTunnel(tunnelID)
	if !exists {
		common.LogInfo("tunnel not found", "tunnel_id", tunnelID, "host", r.Host)
		http.Error(w, "Tunnel not found or offline", http.StatusServiceUnavailable)
		return
	}

	common.LogInfo("proxying web request",
		"tunnel_id", tunnelID,
		"target", tunnel.TargetURL,
		"path", r.URL.Path,
		"method", r.Method)

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
	common.LogInfo("authenticated tunnel access",
		"email", userEmail,
		"tunnel_id", tunnelID,
		"path", r.URL.Path)

	// TODO: Implement actual data plane proxying
	// For now, show a placeholder indicating the tunnel is connected
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "tunn v1 - tunnel connected\n")
	fmt.Fprintf(w, "tunnel_id: %s\n", tunnelID)
	fmt.Fprintf(w, "target: %s\n", tunnel.TargetURL)
	fmt.Fprintf(w, "user: %s\n", userEmail)
	fmt.Fprintf(w, "\nData plane proxying will be implemented in the next phase.\n")
}

// handleApexDomain handles requests to the apex domain (e.g., tunn.to)
func (p *ProxyServer) handleApexDomain(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "tunn v1 proxy server\n")
	fmt.Fprintf(w, "protocol: %s\n", r.Proto)
	fmt.Fprintf(w, "domain: %s\n", p.Domain)
	fmt.Fprintf(w, "environment: %s\n", p.config.Environment)

	// Show active tunnels count
	activeTunnels := p.tunnelServer.GetActiveTunnelCount()
	fmt.Fprintf(w, "\nActive tunnels: %d\n", activeTunnels)
}
