package client

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// The publisher context owns its origin pool. Run keeps it across relay
// reconnects; standalone ServeMessages calls each own a separate pool. Origin,
// TLS and dial settings must remain fixed for the publisher's lifetime.
// WebSockets retain their separate, per-connection socket ownership.
type originPoolKey struct{}

type originPoolSockets struct {
	mu     sync.Mutex
	closed bool
	conns  map[*originPoolSocket]struct{}
}

type originPoolSocket struct {
	net.Conn
	pool *originPoolSockets
}

func (c *originPoolSocket) Close() error {
	c.pool.mu.Lock()
	delete(c.pool.conns, c)
	c.pool.mu.Unlock()
	return c.Conn.Close()
}

func (p *originPoolSockets) track(conn net.Conn) (net.Conn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	tracked := &originPoolSocket{Conn: conn, pool: p}
	p.conns[tracked] = struct{}{}
	p.mu.Unlock()
	return tracked, nil
}

func (p *originPoolSockets) close() {
	p.mu.Lock()
	p.closed = true
	conns := make([]*originPoolSocket, 0, len(p.conns))
	for conn := range p.conns {
		conns = append(conns, conn)
	}
	p.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

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
	sockets := &originPoolSockets{conns: make(map[*originPoolSocket]struct{})}
	dial := transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return sockets.track(conn)
	}
	return transport, func() {
		// Workers have joined, but HTTP/2 can still be retiring canceled
		// streams. Close owned sockets even if the transport sees them as busy.
		sockets.close()
		transport.CloseIdleConnections()
	}
}
