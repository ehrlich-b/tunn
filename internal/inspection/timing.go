package inspection

import "fmt"

// Timing separates local origin I/O from elapsed relay delivery time. Values
// are milliseconds, retaining sub-millisecond precision. Missing is unknown.
type Timing struct {
	OriginTTFBMS  float64 `json:"origin_ttfb_ms"`
	OriginTotalMS float64 `json:"origin_total_ms"`
	TunnelTTFBMS  float64 `json:"tunnel_ttfb_ms"`
	TunnelTotalMS float64 `json:"tunnel_total_ms"`
	SlowSide      string  `json:"slow_side,omitempty"`
}

// Clone detaches snapshots and observer callbacks from retained history.
func (t *Timing) Clone() *Timing {
	if t == nil {
		return nil
	}
	copy := *t
	return &copy
}

func NewTiming(originTTFB, originTotal, relayTTFB, relayTotal int64) *Timing {
	if originTTFB <= 0 || originTotal <= 0 || relayTotal <= 0 {
		return nil
	}
	timing := &Timing{OriginTTFBMS: float64(originTTFB) / 1000, OriginTotalMS: float64(originTotal) / 1000,
		TunnelTTFBMS: float64(max(0, relayTTFB-originTTFB)) / 1000, TunnelTotalMS: float64(max(0, relayTotal-originTotal)) / 1000}
	app, tunnel := timing.OriginTotalMS >= 1000, timing.TunnelTotalMS >= 1000
	switch {
	case app && tunnel:
		timing.SlowSide = "app and tunnel"
	case app:
		timing.SlowSide = "app"
	case tunnel:
		timing.SlowSide = "tunnel"
	}
	return timing
}
func (t *Timing) Summary() string {
	if t == nil {
		return "timing unavailable"
	}
	format := func(ms float64) string {
		if ms >= 1000 {
			return fmt.Sprintf("%.1f s", ms/1000)
		}
		return fmt.Sprintf("%.1f ms", ms)
	}
	summary := fmt.Sprintf("app %s · tunnel %s · app TTFB %s · tunnel TTFB %s", format(t.OriginTotalMS), format(t.TunnelTotalMS), format(t.OriginTTFBMS), format(t.TunnelTTFBMS))
	if t.SlowSide != "" {
		summary += " · slow: " + t.SlowSide
	}
	return summary
}
