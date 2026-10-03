package host

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

// An explicit grant never falls back to a cookie or another bearer credential.
// The dedicated header takes precedence while allowing application Authorization.
func explicitGrantBearer(r *http.Request) (token, header string) {
	for _, name := range []string{"Tunn-Authorization", "Authorization"} {
		values := r.Header.Values(name)
		for _, value := range values {
			parts := strings.Fields(value)
			if len(parts) >= 2 && strings.EqualFold(parts[0], "Bearer") && strings.HasPrefix(parts[1], store.GrantTokenPrefix) {
				if len(parts) != 2 || len(values) != 1 {
					return store.GrantTokenPrefix, name
				}
				return parts[1], name
			}
		}
	}
	return "", ""
}

func (p *ProxyServer) stripPlatformAuthorization(r *http.Request, tunnel *TunnelConnection) *http.Request {
	if len(r.Header.Values("Authorization")) == 0 {
		return r
	}
	probe := r.Clone(r.Context())
	probe.Header = r.Header.Clone()
	probe.Header.Del("Tunn-Authorization")
	_, _, _, recognized := p.getAuthFromTunnelBearer(probe, tunnel)
	grant, _ := explicitGrantBearer(probe)
	reserved := false
	for _, value := range r.Header.Values("Authorization") {
		parts := strings.Fields(value)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && (strings.HasPrefix(parts[1], "tunn_ep_") || p.isPlatformSignedJWT(parts[1])) {
			reserved = true
		}
	}
	if recognized || grant != "" || reserved {
		probe.Header.Del("Authorization")
		return probe
	}
	return r
}

func (p *ProxyServer) admitIngressGrant(w http.ResponseWriter, r *http.Request, tunnel *TunnelConnection, event *store.IngressEvent, token string) bool {
	event.AuthMethod, event.Reason, event.Outcome = "grant", "grant_unavailable", "denied"
	grants, ok := p.storage.(storage.GrantStorage)
	if !ok || !p.storage.Available() {
		http.Error(w, "Grant admission unavailable", http.StatusServiceUnavailable)
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), ingressStorageTimeout)
	defer cancel()
	q := store.GrantAdmissionRequest{AccountID: tunnel.AccountID, EndpointID: tunnel.TunnelID, Token: token, RequestID: event.RequestID}
	admission, err := grants.AdmitGrant(ctx, q)
	if err != nil && ctx.Err() == nil {
		admission, err = grants.AdmitGrant(ctx, q)
	}
	if err != nil || admission == nil {
		http.Error(w, "Grant admission unavailable", http.StatusServiceUnavailable)
		return false
	}
	if admission.GrantID != "" {
		event.CallerID = "grant:" + admission.GrantID
	}
	event.Reason = admission.Reason
	if !admission.Allowed {
		if p.mcpOAuth != nil && (admission.Reason == "grant_invalid" || admission.Reason == "grant_expired" || admission.Reason == "grant_revoked") {
			admission.Status = http.StatusUnauthorized
		}
		w.Header().Set("X-Tunn-Grant-Reason", admission.Reason)
		if admission.Status == http.StatusUnauthorized {
			p.mcpOAuthChallenge(w, tunnel.TunnelID)
		}
		http.Error(w, "Grant denied: "+admission.Reason, admission.Status)
		return false
	}
	event.Outcome = "completed"
	return true
}

// Mutations require an account bearer credential; cookie-only requests cannot
// mint or revoke credentials through a cross-site form. Account IDs are derived
// from verified identity, never the JSON body or a grant capability.
func (p *ProxyServer) handleGrants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie, Authorization, Tunn-Authorization")
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
		return
	}
	email, _, _, authenticated := p.getAuthFromTunnelBearer(r, &TunnelConnection{})
	if !authenticated && r.Method == http.MethodGet {
		email, authenticated = p.getAuthFromCookie(r)
	}
	if !authenticated {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tunn"`)
		http.Error(w, "Account bearer authentication required", http.StatusUnauthorized)
		return
	}
	grants, supported := p.storage.(storage.GrantStorage)
	if !supported || !p.storage.Available() {
		http.Error(w, "Grant storage unavailable", http.StatusServiceUnavailable)
		return
	}
	account, err := p.storage.GetAccountByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "Grant storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if account == nil {
		http.Error(w, "Account not found", http.StatusForbidden)
		return
	}
	grantID := strings.TrimPrefix(r.URL.Path, "/api/grants/")
	if r.URL.Path == "/api/grants" {
		grantID = ""
	}
	if strings.Contains(grantID, "/") || (grantID != "" && r.Method != http.MethodDelete) || (grantID == "" && r.Method == http.MethodDelete) {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := grants.ListGrants(r.Context(), account.ID, r.URL.Query().Get("endpoint"))
		if err != nil {
			grantAPIError(w, err)
			return
		}
		writeGrantJSON(w, http.StatusOK, struct {
			Grants []store.Grant `json:"grants"`
			Route  string        `json:"route"`
		}{list, "/mcp"})
	case http.MethodPost:
		var input struct {
			Endpoint     string `json:"endpoint"`
			Label        string `json:"label"`
			TTLSeconds   int64  `json:"ttl_seconds"`
			RequestLimit int64  `json:"request_limit"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, "Invalid grant request", 400)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF || input.TTLSeconds < 1 || input.TTLSeconds > int64(store.MaxGrantLifetime/time.Second) {
			http.Error(w, "Invalid grant request", 400)
			return
		}
		if tunnel, found := p.tunnelServer.GetTunnel(input.Endpoint); found && tunnel.EndpointProtocol == "tcp" {
			http.Error(w, "Grants support HTTP /mcp endpoints", 400)
			return
		}
		grant, token, err := grants.CreateGrant(r.Context(), store.GrantCreate{AccountID: account.ID, EndpointID: input.Endpoint, Label: input.Label, ExpiresAt: time.Now().UTC().Add(time.Duration(input.TTLSeconds) * time.Second), RequestLimit: input.RequestLimit})
		if err != nil {
			grantAPIError(w, err)
			return
		}
		writeGrantJSON(w, http.StatusCreated, struct {
			Grant *store.Grant `json:"grant"`
			Token string       `json:"token"`
			Route string       `json:"route"`
		}{grant, token, "/mcp"})
	case http.MethodDelete:
		found, err := grants.RevokeGrant(r.Context(), account.ID, grantID)
		if err != nil {
			grantAPIError(w, err)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func grantAPIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrInvalidGrant):
		http.Error(w, "Invalid grant request", http.StatusBadRequest)
	case errors.Is(err, store.ErrGrantNotOwned):
		http.Error(w, "Endpoint not active or not owned", http.StatusForbidden)
	case errors.Is(err, store.ErrGrantScopeUnsupported):
		http.Error(w, "Grants require a registered HTTP or MCP endpoint", http.StatusBadRequest)
	default:
		http.Error(w, "Grant storage unavailable", http.StatusServiceUnavailable)
	}
}

func writeGrantJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
