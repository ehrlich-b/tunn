package host

// =============================================================================
// BANDWIDTH AND QUOTA LIMITS
// =============================================================================
//
// When changing limits, also update copy in these locations:
//   - internal/host/templates/homepage.html (hosted plan copy)
//   - internal/host/templates/terms.html (hosted plan copy)
//   - CLAUDE.md (rate limiting table)
//   - docs/how-it-works.md (rate limiting section)
//
// =============================================================================

// Monthly bandwidth quotas (bytes, SI decimal: 1 GB = 1,000,000,000 bytes)
const (
	FreeQuotaBytes int64 = 10 * 1000 * 1000 * 1000  // 10 GB
	ProQuotaBytes  int64 = 500 * 1000 * 1000 * 1000 // 500 GB
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
