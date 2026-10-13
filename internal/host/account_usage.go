package host

import (
	"sort"
	"strconv"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

// tunnelUsage is one row of the account page's per-tunnel breakdown.
type tunnelUsage struct {
	Name      string
	Requests  string
	Transfer  string
	Percent   int // share of the busiest tunnel's transfer, for the bar
	requests  int64
	bodyBytes int64
}

// usageByTunnel totals this month's usage rows per endpoint, busiest first.
func usageByTunnel(rows []*meterpb.Usage) []tunnelUsage {
	byName := map[string]*tunnelUsage{}
	for _, u := range rows {
		if u == nil || u.Endpoint == "" {
			continue
		}
		t := byName[u.Endpoint]
		if t == nil {
			t = &tunnelUsage{Name: u.Endpoint}
			byName[u.Endpoint] = t
		}
		t.requests += u.AdmittedRequests
		t.bodyBytes += u.RequestBytes + u.ResponseBytes
	}
	out := make([]tunnelUsage, 0, len(byName))
	var top int64
	for _, t := range byName {
		out = append(out, *t)
		top = max(top, t.bodyBytes)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].bodyBytes != out[j].bodyBytes {
			return out[i].bodyBytes > out[j].bodyBytes
		}
		return out[i].Name < out[j].Name
	})
	for i := range out {
		out[i].Requests, out[i].Transfer, out[i].Percent = formatCount(out[i].requests), formatBytes(out[i].bodyBytes), percentOf(out[i].bodyBytes, top)
	}
	return out
}

// percentOf returns used as a whole percent of limit, capped at 100.
func percentOf(used, limit int64) int {
	if limit <= 0 || used <= 0 {
		return 0
	}
	return int(min(used*100/limit, 100))
}

// formatCount prints a count with thousands separators: 41,233.
func formatCount(n int64) string {
	s := strconv.FormatInt(n, 10)
	if n < 0 {
		return s
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// planLimits returns the concurrent tunnel and reserved name limits for a plan.
func planLimits(plan string) (tunnels, names int) {
	if plan == "pro" {
		return storage.ProTunnelLimit, store.MaxReservedSubdomains
	}
	return storage.FreeTunnelLimit, store.FreeReservedSubdomains
}
