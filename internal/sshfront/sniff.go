package sshfront

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"
)

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// TLSListener leaves the ClientHello intact and dispatches SSH on the same raw
// listener. The semaphore and deadline bound stalled pre-handshake clients.
type TLSListener struct {
	net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	ready  chan net.Conn
	once   sync.Once
}

func Share(ctx context.Context, listener net.Listener, serveSSH func(context.Context, net.Conn)) *TLSListener {
	ctx, cancel := context.WithCancel(ctx)
	l := &TLSListener{Listener: listener, ctx: ctx, cancel: cancel, ready: make(chan net.Conn)}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	go func() {
		slots := make(chan struct{}, 128)
		for {
			conn, err := listener.Accept()
			if err != nil {
				cancel()
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				_ = conn.Close()
				continue
			}
			go func() {
				defer func() { <-slots }()
				_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				r := bufio.NewReaderSize(conn, 4096)
				first, err := r.Peek(1)
				if err != nil {
					_ = conn.Close()
					return
				}
				sshProtocol := false
				if first[0] == 'S' {
					banner, e := r.Peek(8)
					sshProtocol = e == nil && string(banner) == "SSH-2.0-"
				}
				_ = conn.SetReadDeadline(time.Time{})
				buffered := bufferedConn{conn, r}
				if sshProtocol {
					// Classification slots must remain available for HTTPS while
					// long-lived SSH sessions use their separate admission limit.
					go serveSSH(ctx, buffered)
					return
				}
				if first[0] != 0x16 {
					_ = conn.Close()
					return
				}
				select {
				case l.ready <- buffered:
				case <-ctx.Done():
					_ = conn.Close()
				}
			}()
		}
	}()
	return l
}
func (l *TLSListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ready:
		return conn, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l *TLSListener) Close() error { l.once.Do(l.cancel); return l.Listener.Close() }
