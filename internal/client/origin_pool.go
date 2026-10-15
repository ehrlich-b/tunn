package client

import (
	"context"
	"net"
	"net/http"
	"time"
)

// The publisher context owns its origin pool. Run keeps it across relay
// reconnects; standalone ServeMessages calls each own a separate pool. Origin,
// TLS and dial settings must remain fixed for the publisher's lifetime.
// WebSockets retain their separate, per-connection socket ownership.
type originPoolKey struct{}

func (s *ServeClient) withOriginPool(ctx context.Context) (context.Context, func()) {
	transport, closePool := s.originHTTPTransport(ctx)
	return context.WithValue(ctx, originPoolKey{}, transport), closePool
}

func (s *ServeClient) originHTTPTransport(ctx context.Context) (http.RoundTripper, func()) {
	if transport, ok := ctx.Value(originPoolKey{}).(http.RoundTripper); ok {
		return transport, func() {}
	}
	// Injected transports belong to the caller, including their idle sockets.
	if s.HTTPTransport != nil {
		return s.HTTPTransport, func() {}
	}
	timeout := s.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	transport := &http.Transport{
		DialContext:           s.localDialContext(),
		TLSClientConfig:       s.localTLSConfig(),
		ForceAttemptHTTP2:     true,
		ResponseHeaderTimeout: timeout,
		// Buffered and streamed requests have separate admission budgets.
		MaxConnsPerHost:     2 * MaxConcurrentRequests,
		MaxIdleConns:        MaxConcurrentRequests,
		MaxIdleConnsPerHost: MaxConcurrentRequests,
		IdleConnTimeout:     90 * time.Second,
	}
	if s.TargetNetwork == "unix" {
		address := s.DialAddress
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", address)
		}
	}
	return transport, transport.CloseIdleConnections
}
