package host

// =============================================================================
// BANDWIDTH AND QUOTA LIMITS
// =============================================================================
//
// When changing limits, also update copy in these locations:
//   - internal/host/templates/homepage.html (line ~476: "1 GB / month")
//   - internal/host/templates/terms.html (line ~124: "Free accounts get 1 GB/month")
//   - CLAUDE.md (rate limiting table)
//   - docs/how-it-works.md (rate limiting section)
//
// =============================================================================

// Monthly bandwidth quotas (bytes, SI decimal: 1 GB = 1,000,000,000 bytes)
const (
	FreeQuotaBytes int64 = 1 * 1000 * 1000 * 1000  // 1 GB
	ProQuotaBytes  int64 = 50 * 1000 * 1000 * 1000 // 50 GB
)

// Per-tunnel bandwidth rate limits (Mbps)
// These cap sustained transfer rates, not burst traffic.
const (
	FreeBandwidthMbps = 200 // 200 Mbps = ~25 MB/s sustained
	ProBandwidthMbps  = 500 // 500 Mbps = ~62.5 MB/s sustained
)

// BurstSeconds controls how much burst traffic is allowed before rate limiting kicks in.
// A higher value means normal web browsing won't trigger limits, only sustained downloads.
const BurstSeconds = 10

// GetQuotaBytes returns the monthly quota in bytes for the given plan.
func GetQuotaBytes(plan string) int64 {
	switch plan {
	case "pro":
		return ProQuotaBytes
	default:
		return FreeQuotaBytes
	}
}
