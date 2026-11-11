package host

import (
	"net/http"
	"strings"

	"github.com/ehrlich-b/tunn/internal/common"
)

const funnelSourceCookie = "__Host-tunn_source"

// Capture only on platform origins, after customer tunnel routing. A host-only
// cookie cannot be read or planted by a publisher on a sibling tunnel origin.
func (p *ProxyServer) captureFunnelSource(w http.ResponseWriter, r *http.Request) *http.Request {
	// Download-only mirrors have no login configuration or signup flow.
	if p.config == nil || !p.isPlatformHost(r.Host) {
		return r
	}
	source := ""
	if cookie, err := r.Cookie(funnelSourceCookie); err == nil {
		source = common.NormalizeFunnelSource(cookie.Value)
	} else {
		source = common.NormalizeFunnelSource(r.URL.Query().Get("src"))
		// Background assets and API probes must not claim a browser's first
		// touch or allocate cookies on disabled authentication routes.
		if !funnelSourceEntry(r) {
			return r.WithContext(common.WithFunnelSource(r.Context(), source))
		}
		http.SetCookie(w, &http.Cookie{
			Name: funnelSourceCookie, Value: source, Path: "/",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			MaxAge: 30 * 24 * 60 * 60,
		})
		w.Header().Set("Cache-Control", "private, no-store")
	}
	return r.WithContext(common.WithFunnelSource(r.Context(), source))
}

// Public entry pages remember direct visits too. An explicitly attributed link
// can enter through another platform route, including an OAuth login start.
func funnelSourceEntry(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.URL.Query().Has("src") {
		return true
	}
	switch r.URL.Path {
	case "/", "/about", "/pricing", "/ngrok-alternative", "/login", "/auth/login", "/upgrade", "/docs", "/agents":
		return true
	}
	return strings.HasPrefix(r.URL.Path, "/docs/") || strings.HasPrefix(r.URL.Path, "/agents/")
}
