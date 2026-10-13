package host

import (
	"crypto/tls"
	"fmt"
)

// Both relay forwarding transports honor the configured CA without changing
// hostname verification or the explicit development-only insecure setting.
func (p *ProxyServer) relayTLSConfig() (*tls.Config, error) {
	if p.config == nil {
		return nil, fmt.Errorf("relay configuration unavailable")
	}
	configuration := &tls.Config{InsecureSkipVerify: p.config.Insecure}
	if p.config.InternalCACert != "" {
		roots, err := loadInternalCA(p.config.InternalCACert)
		if err != nil {
			return nil, err
		}
		configuration.RootCAs = roots
	}
	return configuration, nil
}
