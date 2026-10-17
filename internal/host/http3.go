package host

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const http3DrainTimeout = 3 * time.Second

const http3UDPPayloadSize = 1200

// Expose only PacketConn so the opt-in listener uses individual UDP writes,
// without kernel GSO or ECN. Also enforce the ceiling at the socket boundary:
// quic-go v0.59 can restart MTU probing after migration even when discovery is
// disabled. Reporting an oversized probe as EMSGSIZE makes it a lost probe;
// it cannot reach the peer and raise the validated size used for stream data.
type http3PacketConn struct{ net.PacketConn }

// Preserve quic-go's socket-buffer tuning without exposing UDP OOB methods.
func (c http3PacketConn) SetReadBuffer(size int) error {
	if socket, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return socket.SetReadBuffer(size)
	}
	return errors.ErrUnsupported
}

func (c http3PacketConn) SetWriteBuffer(size int) error {
	if socket, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return socket.SetWriteBuffer(size)
	}
	return errors.ErrUnsupported
}

func (c http3PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) > http3UDPPayloadSize {
		return 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: syscall.EMSGSIZE}
	}
	return c.PacketConn.WriteTo(b, addr)
}

// Track accepted connections independently of HTTP handlers. quic-go's Close
// waits for handlers even after Shutdown's deadline; an unresponsive handler
// must not keep the process alive or prevent sending CONNECTION_CLOSE.
type http3Listener struct {
	*quic.EarlyListener
	mu    sync.Mutex
	conns map[*quic.Conn]struct{}
}

func (l *http3Listener) Accept(ctx context.Context) (*quic.Conn, error) {
	conn, err := l.EarlyListener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.conns[conn] = struct{}{}
	l.mu.Unlock()
	context.AfterFunc(conn.Context(), func() {
		l.mu.Lock()
		delete(l.conns, conn)
		l.mu.Unlock()
	})
	return conn, nil
}

// Called after ServeListener returns, so Accept can no longer add connections.
func (l *http3Listener) closeConnections() {
	l.mu.Lock()
	conns := make([]*quic.Conn, 0, len(l.conns))
	for conn := range l.conns {
		conns = append(conns, conn)
	}
	l.mu.Unlock()
	for _, conn := range conns {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
	}
}

// http3ResetKey must be stable across restarts so that a new transport can
// reset connections whose IDs it no longer knows. Keep its purpose separate
// from JWT signing, and never expose the derived key in logs.
func (p *ProxyServer) http3ResetKey() (quic.StatelessResetKey, error) {
	var secret []byte
	if p.config != nil && p.config.JWTSecret != "" {
		secret = []byte(p.config.JWTSecret)
	} else {
		// Standalone relays without JWT signing still have a persistent TLS key.
		if p.tlsConfig == nil || len(p.tlsConfig.Certificates) == 0 {
			return quic.StatelessResetKey{}, errors.New("HTTP/3 requires a persistent signing or TLS private key")
		}
		var err error
		secret, err = x509.MarshalPKCS8PrivateKey(p.tlsConfig.Certificates[0].PrivateKey)
		if err != nil {
			return quic.StatelessResetKey{}, errors.New("HTTP/3 could not encode TLS private key")
		}
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("tunn/http3/stateless-reset/v1"))
	return quic.StatelessResetKey(mac.Sum(nil)), nil
}

// startHTTP3Server owns the socket and transport until all HTTP/3 connections
// have sent their close frames. ServeListener returns as soon as shutdown stops
// accepting, so cleanup waits for drain or closes QUIC directly at the deadline
// before releasing UDP.
func (p *ProxyServer) startHTTP3Server(ctx context.Context, handler http.Handler) error {
	key, err := p.http3ResetKey()
	if err != nil {
		return err
	}
	common.LogInfo("starting HTTP/3 server", "addr", p.HTTP3Addr)
	conn, err := net.ListenPacket("udp", p.HTTP3Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.HTTP3Addr, err)
	}
	defer conn.Close()
	transport := &quic.Transport{Conn: http3PacketConn{conn}, StatelessResetKey: &key}
	defer transport.Close()
	// Keep TLS's automatic session-ticket rotation. Unknown tickets after a
	// restart fall back to a full handshake. Explicitly reject early data so
	// authenticated HTTP requests cannot be replayed across deployments.
	// A reused UDP path can lose support for a previously validated MTU.
	// quic-go v0.59 does not reduce its packet size after that change: small
	// HEADERS arrive, while DATA and its retransmissions are blackholed.
	// Stay at QUIC's minimum supported UDP payload on this opt-in listener.
	// Disabling discovery alone would retain the larger default initial size.
	earlyListener, err := transport.ListenEarly(http3.ConfigureTLSConfig(p.tlsConfig.Clone()), &quic.Config{
		Allow0RTT:               false,
		InitialPacketSize:       http3UDPPayloadSize,
		DisablePathMTUDiscovery: true,
	})
	if err != nil {
		return err
	}
	listener := &http3Listener{EarlyListener: earlyListener, conns: make(map[*quic.Conn]struct{})}
	defer listener.Close()
	srv := &http3.Server{Handler: handler}
	p.listenerStarted(listenerHTTP3)
	defer p.listenerState.And(^uint32(listenerHTTP3))

	shutdownDone := make(chan struct{})
	stopShutdown := context.AfterFunc(ctx, func() {
		defer close(shutdownDone)
		common.LogInfo("shutting down HTTP/3 server")
		drainCtx, cancel := context.WithTimeout(context.Background(), http3DrainTimeout)
		defer cancel()
		// Shutdown sends GOAWAY and, on deadline, CONNECTION_CLOSE. The
		// outer cleanup enforces the deadline even if handlers never return.
		_ = srv.Shutdown(drainCtx)
	})
	defer func() {
		// An external listener is ours to close. Stop new handshakes while
		// leaving accepted connections and UDP available for drain/close.
		_ = listener.Close()
		if stopShutdown() {
			go func() {
				defer close(shutdownDone)
				_ = srv.Close()
			}()
		}
		timer := time.NewTimer(http3DrainTimeout)
		defer timer.Stop()
		select {
		case <-shutdownDone:
		case <-timer.C:
			// Shutdown can be stuck waiting for a handler that ignores its
			// canceled request context. Close QUIC directly before releasing
			// UDP, and let process exit dispose of any remaining handler.
			listener.closeConnections()
		}
	}()

	if err := srv.ServeListener(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
