package host

import (
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

// platformSessionDomain uses the exact configured request authority, never a
// suffix match to grant platform trust. The apex keeps its existing domain
// cookie. An explicitly configured unrelated PublicAddr gets a host-only cookie;
// browsers must sign in separately on unrelated origins. Publisher namespaces
// cannot be platform login authorities, even if configured as PublicAddr.
func (p *ProxyServer) platformSessionDomain(r *http.Request) (string, error) {
	if p.config == nil || r == nil || !p.isPlatformHost(r.Host) || p.customerHost(r.Host) || extractTunnelID(requestHostname(r.Host), p.config.Domain) != "" {
		return "", fmt.Errorf("invalid platform session authority")
	}
	host, domain := requestHostname(r.Host), requestHostname(p.config.Domain)
	if host == domain || host == "www."+domain {
		return "." + p.config.Domain, nil
	}
	return "", nil
}

func (p *ProxyServer) signedPlatformSession(w http.ResponseWriter, r *http.Request, claims jwt.MapClaims) error {
	domain, err := p.platformSessionDomain(r)
	if err != nil {
		return err
	}
	return p.signedSession(w, claims, authCookieName, domain, authCookieLifetime)
}
