package host

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/golang-jwt/jwt/v4"
)

const funnelSourceCookie = "__Host-tunn_source"
const funnelSourceLifetime = 30 * 24 * time.Hour

// Use the same configured HTTPS login authority as the existing platform login
// navigation. Canonicalize entry pages BEFORE setting a first-touch cookie, so
// subsequent signup on PublicAddr uses that cookie even when the apex is on a
// different domain. No cookies, session claims or handoff tokens cross origins.
func (p *ProxyServer) canonicalFunnelEntry(w http.ResponseWriter, r *http.Request) bool {
	if p.config == nil || !p.isPlatformHost(r.Host) || !funnelSourceEntry(r) || httpsAuthority(r.Host) == httpsAuthority(p.loginAuthority()) {
		return false
	}
	// Existing authenticated account actions stay on their current origin.
	// They already have a signup event and must retain their session and CSRF
	// bindings (for example, checkout can start on either platform host).
	if p.isAuthenticated(r) {
		return false
	}
	// A configured public address in the publisher namespace is routed as a
	// tunnel, not a platform origin. Do not send browser attribution there.
	if httpsAuthority(p.loginAuthority()) == "" || extractTunnelID(requestHostname(p.loginAuthority()), p.Domain) != "" {
		http.Error(w, "Login origin unavailable", http.StatusServiceUnavailable)
		return true
	}
	query := r.URL.Query()
	if query.Has("src") {
		query.Set("src", common.NormalizeFunnelSource(query.Get("src")))
	}
	target := &url.URL{Scheme: "https", Host: p.loginAuthority(), Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: query.Encode()}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, target.String(), http.StatusFound)
	return true
}

func (p *ProxyServer) browserFunnelSource(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(funnelSourceCookie)
	if err != nil {
		return "", false
	}
	claims, ok := p.parseDomainToken(cookie.Value, "funnel_source")
	source, _ := claims["source"].(string)
	return source, ok && claims["aud"] == httpsAuthority(r.Host) && source != "" && common.NormalizeFunnelSource(source) == source
}

// Capture only on platform origins, after customer tunnel routing. A host-only
// cookie cannot be read or planted by a publisher on a sibling tunnel origin.
func (p *ProxyServer) captureFunnelSource(w http.ResponseWriter, r *http.Request) *http.Request {
	// Download-only mirrors have no login configuration or signup flow.
	if !p.visitorJWTConfigured() || !p.isPlatformHost(r.Host) {
		return r
	}
	source, valid := p.browserFunnelSource(r)
	if !valid {
		source = "direct"
		// Background assets and API probes must not claim a browser's first
		// touch or allocate cookies on disabled authentication routes.
		if !funnelSourceEntry(r) {
			return r.WithContext(common.WithFunnelSource(r.Context(), source))
		}
		source = common.NormalizeFunnelSource(r.URL.Query().Get("src"))
		raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"type": "funnel_source", "source": source, "aud": httpsAuthority(r.Host),
			"iat": p.currentTime().Unix(), "exp": p.currentTime().Add(funnelSourceLifetime).Unix(),
		}).SignedString(p.getJWTSigningKey())
		if err != nil {
			return r
		}
		http.SetCookie(w, &http.Cookie{
			Name: funnelSourceCookie, Value: raw, Path: "/",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			MaxAge: int(funnelSourceLifetime.Seconds()),
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
