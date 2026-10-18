package host

import (
	"context"
	"encoding/json"
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
	owners := map[string]string{}
	for _, tunnel := range connections {
		if tunnel.AccountID == "" {
			continue
		}
		owner, ok := owners[tunnel.AccountID]
		if !ok {
			if server.storage == nil || !server.storage.Available() {
				return nil, status.Error(codes.Unavailable, "Account authority unavailable")
			}
			account, err := server.storage.GetAccount(ctx, tunnel.AccountID)
			if err != nil || account == nil {
				return nil, status.Error(codes.Unavailable, "Account authority unavailable")
			}
			owner = account.ID
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
		row := &internalpb.AccountTunnel{Name: tunnel.TunnelID, Kind: kind, PublicUrl: "https://" + tunnel.TunnelID + "." + server.cfg.Domain, ConnectedSinceUnix: tunnel.Connected.Unix(), ClientVersion: tunnel.ClientVersion, ClientHost: tunnel.ClientHost}
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
		rows []*internalpb.AccountTunnel
		err  error
	}
	results := make(chan result, len(p.nodeClients)+1)
	request := &internalpb.ListAccountTunnelsRequest{AccountId: owner}
	go func() {
		out, err := NewInternalServer(p.tunnelServer, "", false).ListAccountTunnels(ctx, request)
		results <- result{out.GetTunnels(), err}
	}()
	for _, peer := range p.nodeClients {
		go func() { out, err := peer.ListAccountTunnels(ctx, request); results <- result{out.GetTunnels(), err} }()
	}
	rows := make([]accountTunnel, 0)
	seen := map[string]bool{}
	complete := true
	for range len(p.nodeClients) + 1 {
		select {
		case res := <-results:
			if res.err != nil {
				complete = false
				continue
			}
			for _, tunnel := range res.rows {
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
		case <-ctx.Done():
			complete = false
		}
	}
	// Resolve customer app names through the existing owner-scoped domain API.
	if p.domains != nil && len(rows) > 0 {
		domains, err := p.domains.List(ctx, &domainpb.Owner{Owner: owner})
		if err != nil {
			complete = false
		} else {
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
