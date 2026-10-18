package host

import (
	"net"
	"net/url"
)

// relayPublicURL uses the configured relay HTTPS port for both the platform
// and publisher origins. The default HTTPS port is omitted from public links.
func relayPublicURL(domain, publicAddr, endpoint string) string {
	host := domain
	if endpoint != "" {
		host = endpoint + "." + host
	}
	u, err := url.Parse("https://" + publicAddr)
	if err == nil && u.Port() != "" && u.Port() != "443" {
		host = net.JoinHostPort(host, u.Port())
	}
	return "https://" + host
}
