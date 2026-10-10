package tunn

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// PublishHandler publishes an existing handler using the core's HTTP and
// WebSocket adapters over private in-process pipes. It opens no local TCP port.
// Origin must be blank. Requests receive cancellation when the tunnel ends.
// The caller owns handler state and any goroutines the handler starts.
func PublishHandler(ctx context.Context, handler http.Handler, options Options) (*Tunnel, error) {
	if handler == nil {
		return nil, invalid("a handler is required")
	}
	if options.Origin != "" {
		return nil, invalid("PublishHandler requires an empty Origin")
	}
	options.Origin = "http://sdk-handler.invalid"
	origin := &handlerOrigin{handler: handler, incoming: make(chan net.Conn), done: make(chan struct{}), served: make(chan struct{})}
	return publish(ctx, options, origin)
}

type handlerOrigin struct {
	handler  http.Handler
	incoming chan net.Conn
	done     chan struct{}
	served   chan struct{}
	once     sync.Once
	server   *http.Server
	mu       sync.Mutex
	accepted map[net.Conn]struct{}
}

func (o *handlerOrigin) start(ctx context.Context) {
	o.accepted = make(map[net.Conn]struct{})
	o.server = &http.Server{Handler: o.handler, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { defer close(o.served); _ = o.server.Serve(o) }()
}

func (o *handlerOrigin) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case o.incoming <- server:
		return client, nil
	case <-o.done:
		_ = client.Close()
		_ = server.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = client.Close()
		_ = server.Close()
		return nil, ctx.Err()
	}
}

func (o *handlerOrigin) Accept() (net.Conn, error) {
	select {
	case conn := <-o.incoming:
		o.mu.Lock()
		defer o.mu.Unlock()
		select {
		case <-o.done:
			_ = conn.Close()
			return nil, net.ErrClosed
		default:
		}
		o.accepted[conn] = struct{}{}
		return &handlerConn{Conn: conn, origin: o}, nil
	case <-o.done:
		return nil, net.ErrClosed
	}
}
func (o *handlerOrigin) Close() error {
	o.once.Do(func() {
		close(o.done)
		o.mu.Lock()
		defer o.mu.Unlock()
		// Include hijacked WebSocket connections, which http.Server.Close
		// deliberately leaves alone. These pipe endpoints belong to the SDK.
		for connection := range o.accepted {
			_ = connection.Close()
		}
	})
	return nil
}
func (o *handlerOrigin) Addr() net.Addr { return handlerAddress{} }
func (o *handlerOrigin) close()         { _ = o.server.Close(); <-o.served }

type handlerAddress struct{}

func (handlerAddress) Network() string { return "pipe" }
func (handlerAddress) String() string  { return "sdk-handler.invalid:80" }

type handlerConn struct {
	net.Conn
	origin *handlerOrigin
}

func (c *handlerConn) Close() error {
	err := c.Conn.Close()
	c.origin.mu.Lock()
	delete(c.origin.accepted, c.Conn)
	c.origin.mu.Unlock()
	return err
}
