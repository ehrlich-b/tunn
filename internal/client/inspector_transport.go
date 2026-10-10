package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
)

func (s *ServeClient) inspectionTransport() *http.Transport {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: s.SkipLocalTLSVerify}, ForceAttemptHTTP2: true, DialContext: s.DialContext}
	if s.TargetNetwork == "unix" {
		address := s.DialAddress
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", address)
		}
	}
	return transport
}
