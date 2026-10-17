package host

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
)

// HTTP/2 cancels request contexts for both RST_STREAM and socket loss. Keep the
// socket's terminal event so a lost connection cannot become a client stop.
type publisherTransportKey struct{}
type publisherTransportState struct{ stop atomic.Pointer[publisherStop] }
type publisherListener struct{ net.Listener }
type publisherTransport struct {
	net.Conn
	state *publisherTransportState
}

func (l publisherListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &publisherTransport{Conn: c, state: &publisherTransportState{}}, nil
}

func publisherConnContext(ctx context.Context, c net.Conn) context.Context {
	if secured, ok := c.(*tls.Conn); ok {
		c = secured.NetConn()
	}
	if transport, ok := c.(*publisherTransport); ok {
		return context.WithValue(ctx, publisherTransportKey{}, transport.state)
	}
	return ctx
}

func (c *publisherTransport) failed(err error) {
	ended := &publisherStop{reason: publisherTransportLoss, detail: "Publisher connection lost"}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		ended.reason, ended.detail = publisherTimeout, "Publisher keepalive timed out"
	}
	c.state.stop.CompareAndSwap(nil, ended)
}

func (c *publisherTransport) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.failed(err)
	}
	return n, err
}
func (c *publisherTransport) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.failed(err)
	}
	return n, err
}
func (c *publisherTransport) Close() error {
	c.state.stop.CompareAndSwap(nil, &publisherStop{reason: publisherEviction, detail: "Relay closed publisher connection"})
	return c.Conn.Close()
}
