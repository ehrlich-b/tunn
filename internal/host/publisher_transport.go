package host

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"

	"golang.org/x/net/http2"
)

type publisherRequestKey struct{}

// HTTP/2 closes a request body with the stream's own terminal event, even if
// the socket is closed immediately afterwards. Retain it for legacy clients
// whose RST_STREAM cancellation predates explicit graceful-stop negotiation.
type publisherRequestBody struct {
	io.ReadCloser
	ctx  context.Context
	done chan struct{}
	err  error // published by closing done; the gRPC transport has one reader
}

func (b *publisherRequestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		select {
		case <-b.done:
		default:
			b.err = err
			close(b.done)
		}
	}
	return n, err
}

func (b *publisherRequestBody) Close() error {
	if b.ctx.Err() != nil {
		// gRPC closes the body concurrently with its reader on request
		// cancellation. Preserve the HTTP/2 event before Close can replace
		// it with "body closed by handler".
		<-b.done
	}
	return b.ReadCloser.Close()
}

func (b *publisherRequestBody) legacyStop() *publisherStop {
	if b.ctx.Err() == nil {
		return nil
	}
	// Request cancellation closes the HTTP/2 body pipe. Wait for that event
	// rather than whichever gRPC cancellation goroutine happened to win.
	<-b.done
	var reset http2.StreamError
	if errors.Is(b.err, io.EOF) || errors.As(b.err, &reset) && reset.Code == http2.ErrCodeCancel {
		return nil
	}
	return &publisherStop{reason: publisherTransportLoss, detail: "Publisher connection lost"}
}

func publisherRequest(r *http.Request) *http.Request {
	body := &publisherRequestBody{ReadCloser: r.Body, ctx: r.Context(), done: make(chan struct{})}
	r = r.WithContext(context.WithValue(r.Context(), publisherRequestKey{}, body))
	r.Body = body
	return r
}

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
