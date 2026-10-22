package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const accountTunnelPreviewLimit = 4

// Publisher-supplied display text is bounded and never interpreted as markup.
func boundedClientLabel(value string) string {
	runes := []rune(value)
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, string(runes[:min(len(runes), 80)]))
}

type accountTunnel struct {
	Name           string     `json:"name"`
	Kind           string     `json:"kind"`
	PublicURL      string     `json:"public_url"`
	ConnectedSince time.Time  `json:"connected_since"`
	ClientVersion  string     `json:"client_version"`
	ClientHost     string     `json:"client_host"`
	LastRequest    *time.Time `json:"last_request,omitempty"`
}

func relativeTunnelTime(at time.Time, ago bool) string {
	d := max(time.Duration(0), time.Since(at))
	var label string
	switch {
	case d < time.Minute:
		label = "now"
	case d < time.Hour:
		label = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		label = fmt.Sprintf("%dh", int(d.Hours()))
	default:
		label = fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	if ago && label != "now" {
		label += " ago"
	}
	return label
}

func (t accountTunnel) Duration() string { return relativeTunnelTime(t.ConnectedSince, false) }
func (t accountTunnel) LastRequestRelative() string {
	if t.LastRequest == nil {
		return ""
	}
	return relativeTunnelTime(*t.LastRequest, true)
}
func (t accountTunnel) URLStart() string {
	r := []rune(t.PublicURL)
	return string(r[:max(0, len(r)-20)])
}
func (t accountTunnel) URLEnd() string {
	r := []rune(t.PublicURL)
	return string(r[max(0, len(r)-20):])
}

// The node-secret interceptor protects this RPC. Ownership is resolved from
// immutable account UUIDs so merges work without reconnecting the publisher.
func (s *InternalServer) ListAccountTunnels(ctx context.Context, req *internalpb.ListAccountTunnelsRequest) (*internalpb.ListAccountTunnelsResponse, error) {
	if req.AccountId == "" {
		return nil, status.Error(codes.InvalidArgument, "Account required")
	}
	out := &internalpb.ListAccountTunnelsResponse{}
	if s.tunnelServer == nil {
		return out, nil
	}
	server := s.tunnelServer
	server.mu.RLock()
	connections := make([]*TunnelConnection, 0, len(server.tunnels))
	for _, tunnel := range server.tunnels {
		connections = append(connections, tunnel)
	}
	server.mu.RUnlock()
	if server.storage == nil || !server.storage.Available() {
		return nil, status.Error(codes.Unavailable, "Account authority unavailable")
	}
	requested, err := server.storage.GetAccount(ctx, req.AccountId)
	if err != nil || requested == nil || requested.ID != req.AccountId {
		return nil, status.Error(codes.Unavailable, "Account authority unavailable")
	}
	owners := map[string]string{req.AccountId: requested.ID}
	for _, tunnel := range connections {
		if tunnel.AccountID == "" {
			continue
		}
		owner, ok := owners[tunnel.AccountID]
		if !ok {
			account, err := server.storage.GetAccount(ctx, tunnel.AccountID)
			if err != nil {
				// Uncertainty about another owner cannot authorize this row.
				// Keep proven rows, but do not claim a complete inventory.
				out.Partial = true
			} else if account != nil {
				owner = account.ID
			}
			// A missing account is a known deletion, not an authority outage.
			// Cache failures too, so multiple rows never repeat a failed lookup.
			owners[tunnel.AccountID] = owner
		}
		if owner != req.AccountId {
			continue
		}
		kind := "HTTP"
		if tunnel.EndpointProtocol == "tcp" {
			kind = "TCP"
		} else if tunnel.TargetURL == "mcp" {
			kind = "MCP"
		}
		row := &internalpb.AccountTunnel{Name: tunnel.TunnelID, Kind: kind, PublicUrl: relayPublicURL(server.cfg.Domain, server.cfg.PublicAddr, tunnel.TunnelID), ConnectedSinceUnix: tunnel.Connected.Unix(), ClientVersion: tunnel.ClientVersion, ClientHost: tunnel.ClientHost}
		if kind == "MCP" {
			row.PublicUrl += "/mcp"
		}
		tunnel.inspectorMu.Lock()
		history := tunnel.inspector
		tunnel.inspectorMu.Unlock()
		if history != nil {
			if at := history.LastRequestAt(); !at.IsZero() {
				row.LastRequestUnix = at.Unix()
			}
		}
		out.Tunnels = append(out.Tunnels, row)
	}
	return out, nil
}

// Query live relay maps rather than durable reservations, which can outlive a
// publisher or a crashed node. All peers share one deadline and run concurrently.
func (p *ProxyServer) accountTunnels(ctx context.Context, owner string) ([]accountTunnel, bool) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	type result struct {
		rows    []*internalpb.AccountTunnel
		partial bool
		err     error
	}
	results := make(chan result, len(p.nodeClients)+1)
	request := &internalpb.ListAccountTunnelsRequest{AccountId: owner}
	go func() {
		out, err := NewInternalServer(p.tunnelServer, "", false).ListAccountTunnels(ctx, request)
		results <- result{out.GetTunnels(), out.GetPartial(), err}
	}()
	for _, peer := range p.nodeClients {
		go func() {
			out, err := peer.ListAccountTunnels(ctx, request)
			results <- result{out.GetTunnels(), out.GetPartial(), err}
		}()
	}
	// Start optional enrichment alongside relay queries; a slow peer must not
	// consume the time needed to resolve already-known app inventory.
	type domainResult struct {
		domains *domainpb.DomainList
		err     error
	}
	domainResults := make(chan domainResult, 1)
	if p.domains != nil {
		go func() {
			domains, err := p.domains.List(ctx, &domainpb.Owner{Owner: owner})
			domainResults <- domainResult{domains, err}
		}()
	}
	complete := true
	candidates := make([]*internalpb.AccountTunnel, 0)
	consume := func(res result) {
		if res.err != nil || res.partial {
			complete = false
		}
		if res.err == nil {
			candidates = append(candidates, res.rows...)
		}
	}
	remaining := len(p.nodeClients) + 1
collect:
	for remaining > 0 {
		select {
		case res := <-results:
			consume(res)
			remaining--
		case <-ctx.Done():
			complete = false
			// Prefer every result already delivered before the deadline, even
			// when cancellation and a buffered healthy response are both ready.
			for remaining > 0 {
				select {
				case res := <-results:
					consume(res)
					remaining--
				default:
					break collect
				}
			}
		}
	}
	// During reconnects two relays can briefly report the same name. Choose
	// the newest connection deterministically before applying app display names.
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.GetName() != b.GetName() {
			return a.GetName() < b.GetName()
		}
		if a.GetConnectedSinceUnix() != b.GetConnectedSinceUnix() {
			return a.GetConnectedSinceUnix() > b.GetConnectedSinceUnix()
		}
		return a.GetPublicUrl() < b.GetPublicUrl()
	})
	rows := make([]accountTunnel, 0, len(candidates))
	seen := map[string]bool{}
	for _, tunnel := range candidates {
		if tunnel == nil || seen[tunnel.Name] {
			continue
		}
		seen[tunnel.Name] = true
		row := accountTunnel{Name: tunnel.Name, Kind: tunnel.Kind, PublicURL: tunnel.PublicUrl, ConnectedSince: time.Unix(tunnel.ConnectedSinceUnix, 0).UTC(), ClientVersion: tunnel.ClientVersion, ClientHost: tunnel.ClientHost}
		if tunnel.LastRequestUnix > 0 {
			at := time.Unix(tunnel.LastRequestUnix, 0).UTC()
			row.LastRequest = &at
		}
		rows = append(rows, row)
	}
	// Enrichment failure retains relay URLs and proven-owned inventory.
	if p.domains != nil && len(rows) > 0 {
		var enrichment domainResult
		select {
		case enrichment = <-domainResults:
		default:
			select {
			case enrichment = <-domainResults:
			case <-ctx.Done():
				enrichment.err = ctx.Err()
			}
		}
		if enrichment.err != nil {
			complete = false
		} else {
			domains := enrichment.domains
			for i := range rows {
				tunnelID := rows[i].Name
				for _, domain := range domains.GetDomains() {
					if domain.State != "ready" || domain.VerifiedUntil <= time.Now().Unix() {
						continue
					}
					if strings.HasPrefix(domain.Name, "*.") {
						for _, app := range domain.AppNames {
							if app.Tunnel == tunnelID {
								rows[i].Name, rows[i].Kind, rows[i].PublicURL = app.Label, "app", "https://"+app.Label+strings.TrimPrefix(domain.Name, "*")
								break
							}
						}
					} else if domain.Tunnel == tunnelID {
						rows[i].Kind, rows[i].PublicURL = "app", "https://"+domain.Name
					}
				}
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].LastRequest, rows[j].LastRequest
		if a != nil && b == nil {
			return true
		}
		if a == nil && b != nil {
			return false
		}
		if a != nil && b != nil && !a.Equal(*b) {
			return a.After(*b)
		}
		if rows[i].Name == rows[j].Name {
			return rows[i].PublicURL < rows[j].PublicURL
		}
		return rows[i].Name < rows[j].Name
	})
	return rows, complete
}

func (p *ProxyServer) handleAccountTunnels(w http.ResponseWriter, r *http.Request) {
	w = protectResponse(w)
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Platform origin required", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	account := p.revenueAccount(w, r)
	if account == nil {
		return
	}
	rows, complete := p.accountTunnels(r.Context(), account.ID)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(struct {
		Tunnels  []accountTunnel `json:"tunnels"`
		Complete bool            `json:"complete"`
	}{rows, complete})
}
