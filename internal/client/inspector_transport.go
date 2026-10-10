package client

import (
	"context"
	"net"
	"net/http"
)

func (s *ServeClient) inspectionTransport() *http.Transport {
	transport := &http.Transport{TLSClientConfig: s.localTLSConfig(), ForceAttemptHTTP2: true, DialContext: s.localDialContext()}
	if s.TargetNetwork == "unix" {
		address := s.DialAddress
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", address)
		}
	}
	return transport
}
