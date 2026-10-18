package host

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/inspection"
	"github.com/ehrlich-b/tunn/internal/storage"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

//go:embed templates/inspector.html
var webInspectorTemplate string

var webInspectorHTML = strings.Replace(webInspectorTemplate, "// REPLAY_VALIDATION", inspection.ReplayValidationJS, 1)

const inspectorCSRFAction = "inspector-replay"

type inspectorReplayKey struct{}
type inspectorReplay struct {
	tunnel         *TunnelConnection
	owner          string
	originalID     uint64
	browserRequest *http.Request
	result         inspection.Event
}

func (t *TunnelConnection) inspectionHistory() *inspection.History {
	t.inspectorMu.Lock()
	defer t.inspectorMu.Unlock()
	if t.inspector == nil {
		history, err := inspection.NewHistory()
		if err != nil {
			return nil
		}
		t.inspector = history
	}
	return t.inspector
}

// Inspector access is account-bound browser authentication. Endpoint, grant,
// device and legacy email-only credentials never identify an inspector owner.
func (p *ProxyServer) inspectorOwner(w http.ResponseWriter, r *http.Request) *storage.Account {
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Platform origin required", http.StatusForbidden)
		return nil
	}
	claims, ok := p.accountSession(r)
	if !ok {
		http.Error(w, "Owner sign-in required. Sign in again to refresh your session.", http.StatusUnauthorized)
		return nil
	}
	account, err := p.browserSessionAccount(w, r, claims)
	if err != nil {
		http.Error(w, "Account service unavailable", http.StatusServiceUnavailable)
		return nil
	}
	if account == nil {
		http.Error(w, "Owner sign-in required. Sign in again to refresh your session.", http.StatusUnauthorized)
		return nil
	}
	if account.ID == "" || account.OperationalState != "active" {
		http.Error(w, "Active owner account required", http.StatusForbidden)
		return nil
	}
	return account
}
func (p *ProxyServer) handleInspectorPage(w http.ResponseWriter, r *http.Request) {
	w = protectResponse(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	account := p.inspectorOwner(w, r)
	if account == nil {
		return
	}
	csrf, err := p.createCSRFToken(r, inspectorCSRFAction)
	if err != nil {
		http.Error(w, "Unable to prepare inspector", 503)
		return
	}
	nonce, err := generateRandomState()
	if err != nil {
		http.Error(w, "Unable to prepare inspector", 503)
		return
	}
	tmpl, err := template.New("inspector").Parse(withPageHead(webInspectorHTML))
	if err != nil {
		http.Error(w, "Inspector unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; manifest-src 'self'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	_ = tmpl.Execute(w, struct {
		Email, CSRF, Nonce string
		CSS                template.CSS
	}{account.PrimaryEmail, csrf, nonce, template.CSS(baseCSS)})
}
func inspectorJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func inspectorBinding(r *http.Request) string {
	cookie, _ := r.Cookie(authCookieName)
	if cookie == nil {
		return ""
	}
	digest := sha256.Sum256([]byte(cookie.Value))
	return hex.EncodeToString(digest[:])
}

// Discover and route once. Every relay independently resolves the browser
// account and proves local ownership; history is never replicated or persisted.
func (p *ProxyServer) routeInspector(w http.ResponseWriter, r *http.Request, endpoint string) bool {
	if r.Header.Get("Tunn-Inspector-Hop") != "" {
		return false
	}
	p.cacheMu.RLock()
	node := p.tunnelCache[endpoint]
	p.cacheMu.RUnlock()
	if node == "" {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		for _, client := range p.nodeClients {
			response, err := client.FindTunnel(ctx, &internalpb.FindTunnelRequest{TunnelId: endpoint})
			if err == nil && response.Found {
				node = response.NodeAddress
				break
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	if node == "" {
		return false
	}
	forwarded := r.Clone(r.Context())
	forwarded.Header.Set("Tunn-Inspector-Hop", "1")
	p.proxyToNode(w, forwarded, node, endpoint)
	return true
}

func (p *ProxyServer) inspectorEndpoints(w http.ResponseWriter, r *http.Request, account *storage.Account) {
	endpoints := map[string]bool{}
	if backend := p.sharingBackend(); backend != nil {
		resources, err := backend.Sharing(r.Context(), &meterpb.SharingRequest{Operation: "list", Owner: account.ID})
		if err != nil {
			http.Error(w, "Endpoint authority unavailable", 503)
			return
		}
		for _, resource := range resources.Resources {
			if isValidDNSLabel(resource.Endpoint) {
				endpoints[resource.Endpoint] = true
			}
		}
	}
	// Include older HTTP publishers that predate durable sharing resources.
	p.tunnelServer.mu.RLock()
	tunnels := make([]*TunnelConnection, 0, len(p.tunnelServer.tunnels))
	for _, tunnel := range p.tunnelServer.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	p.tunnelServer.mu.RUnlock()
	for _, tunnel := range tunnels {
		if tunnel.EndpointProtocol == "tcp" {
			continue
		}
		owner, err := p.currentTunnelAccount(r.Context(), tunnel)
		if err != nil {
			http.Error(w, "Endpoint authority unavailable", 503)
			return
		}
		if owner != nil && owner.ID == account.ID {
			endpoints[tunnel.TunnelID] = true
		}
	}
	names := make([]string, 0, len(endpoints))
	for name := range endpoints {
		names = append(names, name)
	}
	sort.Strings(names)
	truncated := len(names) > 200
	if truncated {
		names = names[:200]
	}
	inspectorJSON(w, 200, struct {
		Endpoints []string `json:"endpoints"`
		Truncated bool     `json:"truncated"`
	}{names, truncated})
}
func (p *ProxyServer) handleInspectorAPI(w http.ResponseWriter, r *http.Request) {
	w = protectResponse(w)
	account := p.inspectorOwner(w, r)
	if account == nil {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/inspector/"), "/")
	if len(parts) == 1 && parts[0] == "endpoints" && r.Method == http.MethodGet {
		p.inspectorEndpoints(w, r, account)
		return
	}
	if len(parts) < 2 || len(parts) > 4 || !isValidDNSLabel(parts[0]) || parts[1] != "requests" {
		http.NotFound(w, r)
		return
	}
	get := r.Method == http.MethodGet && (len(parts) == 2 || len(parts) == 3)
	post := r.Method == http.MethodPost && len(parts) == 4 && (parts[3] == "prepare" || parts[3] == "replay")
	if !get && !post {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	if post {
		// Reuse the existing session-bound CSRF and exact HTTPS origin checks
		// while leaving the bounded JSON body available for decoding.
		csrfRequest := r.Clone(r.Context())
		csrfRequest.PostForm = url.Values{"csrf_token": {r.Header.Get("X-Tunn-CSRF")}}
		if !p.requireCSRFToken(w, csrfRequest, inspectorCSRFAction) {
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			http.Error(w, "JSON body required", 415)
			return
		}
	}
	tunnel, exists := p.tunnelServer.GetTunnel(parts[0])
	if !exists {
		if p.routeInspector(w, r, parts[0]) {
			return
		}
		http.Error(w, "Endpoint offline. Its request list cleared when the tunnel disconnected.", 503)
		return
	}
	owner, err := p.currentTunnelAccount(r.Context(), tunnel)
	if err != nil {
		http.Error(w, "Endpoint authority unavailable", 503)
		return
	}
	if owner == nil || owner.ID != account.ID || owner.OperationalState != "active" {
		http.Error(w, "Only the endpoint owner can inspect requests", 403)
		return
	}
	if tunnel.EndpointProtocol == "tcp" {
		http.Error(w, "Request history supports HTTP endpoints", 400)
		return
	}
	history := tunnel.inspectionHistory()
	if history == nil {
		http.Error(w, "Inspector unavailable", 503)
		return
	}
	replaySupported := tunnel.Supports(common.CapabilityHTTPOriginReplayV1) && tunnel.Supports(common.CapabilityHTTPStreamV1)
	if len(parts) == 2 {
		inspectorJSON(w, 200, struct {
			Session         string             `json:"session"`
			Events          []inspection.Event `json:"events"`
			Limit           int                `json:"limit"`
			ReplaySupported bool               `json:"replay_supported"`
		}{history.Session(), history.Snapshot(), inspection.EventLimit, replaySupported})
		return
	}
	id, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || id == 0 {
		http.NotFound(w, r)
		return
	}
	event, exists := history.Event(id)
	if !exists {
		http.Error(w, "Request no longer retained. Refresh the list.", 404)
		return
	}
	if get {
		inspectorJSON(w, 200, event)
		return
	}
	if !replaySupported {
		http.Error(w, "Upgrade tunn on the machine running this tunnel to replay requests", 409)
		return
	}
	var input struct {
		Session   string `json:"session"`
		Action    string `json:"action,omitempty"`
		Confirmed bool   `json:"confirmed,omitempty"`
		inspection.Request
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, inspection.ReplayInputLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "Invalid replay input (128 KiB maximum)", 400)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "Invalid replay input", 400)
		return
	}
	if input.Session != history.Session() {
		http.Error(w, "Your tunnel reconnected. Refresh the list and try again", 409)
		return
	}
	if parts[3] == "prepare" {
		action, expires, err := history.Prepare(id, inspectorBinding(r), p.currentTime())
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		inspectorJSON(w, 200, struct {
			Action  string    `json:"action"`
			Expires time.Time `json:"expires_at"`
		}{action, expires})
		return
	}
	if !input.Confirmed {
		http.Error(w, "Explicit replay confirmation required", 400)
		return
	}
	original, path, headers, body, done, err := history.BeginReplay(id, input.Session, input.Action, inspectorBinding(r), input.Request, p.currentTime())
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	defer done()
	// The validated Host/path select the same endpoint through ordinary routing;
	// there is no user-supplied target URL. Pinning prevents name reuse races.
	replay := &inspectorReplay{tunnel: tunnel, owner: account.ID, originalID: id, browserRequest: r}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, inspectorReplayKey{}, replay)
	request, err := http.NewRequestWithContext(ctx, original.Method, "https://"+headers["Host"]+path, strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "Unable to construct replay request", 400)
		return
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	request.Header.Del("Host")
	request.RemoteAddr, request.TLS = r.RemoteAddr, r.TLS
	// Preserve a deliberately reconstructed zero-length body, including its
	// representation headers, without ever retaining it in history.
	request.ContentLength = int64(len(body))
	output := &inspectorReplayResponse{header: make(http.Header), status: 200}
	dispatchInspectorReplay(p, output, request)
	if replay.result.ID == 0 {
		status := output.status
		if status < 400 {
			status = 503
		}
		reason := output.header.Get("Tunn-Limit-Reason")
		if reason == "" {
			reason = "Replay did not reach the origin. Refresh before preparing another action."
		}
		inspectorJSON(w, status, struct {
			Error string `json:"error"`
		}{reason})
		return
	}
	inspectorJSON(w, 200, struct {
		Event inspection.Event `json:"event"`
	}{replay.result})
}

// The ordinary ingress boundary aborts a started, truncated HTTP response.
// Here that response was written to an in-memory sink, so translate only this
// sentinel into the already-recorded failure event for the dashboard. Other
// panics retain their normal behavior and all forwarding cleanup still runs.
func dispatchInspectorReplay(p *ProxyServer, output http.ResponseWriter, request *http.Request) {
	defer func() {
		if failure := recover(); failure != nil && failure != http.ErrAbortHandler {
			panic(failure)
		}
	}()
	p.handleWebProxy(output, request)
}

// Origin response bytes are counted, never exposed or retained by replay. A
// bounded sink aborts a newly streaming or oversized response without retry.
type inspectorReplayResponse struct {
	header    http.Header
	status    int
	bytes     int64
	committed bool
}

func (w *inspectorReplayResponse) Header() http.Header { return w.header }
func (w *inspectorReplayResponse) WriteHeader(status int) {
	if status >= 200 && !w.committed {
		w.status = status
		w.committed = true
	}
}
func (w *inspectorReplayResponse) Write(p []byte) (int, error) {
	w.committed = true
	remaining := int64(1024*1024) - w.bytes
	n := min(int64(len(p)), remaining)
	w.bytes += n
	if n < int64(len(p)) {
		return int(n), errors.New("replay response exceeds 1 MiB")
	}
	return int(n), nil
}
func (w *inspectorReplayResponse) Flush() {}
