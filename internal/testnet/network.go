// Package testnet supplies bounded, full-duplex in-memory sockets for protocol
// tests in environments that prohibit loopback listeners.
package testnet

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Pair permits simultaneous SSH identification banners and retains buffered
// bytes until the reader drains them, including after the writer closes.
func Pair() (net.Conn, net.Conn) {
	a, b := &conn{}, &conn{}
	a.in = make(chan []byte, 8)
	b.in = make(chan []byte, 8)
	a.done = make(chan struct{})
	b.done = make(chan struct{})
	a.changed = make(chan struct{})
	b.changed = make(chan struct{})
	a.peer = b
	b.peer = a
	return a, b
}

type conn struct {
	peer                        *conn
	in                          chan []byte
	done, changed               chan struct{}
	once                        sync.Once
	readMu, writeMu, mu         sync.Mutex
	pending                     []byte
	readDeadline, writeDeadline time.Time
}

func (c *conn) deadline(read bool) (<-chan time.Time, <-chan struct{}, func()) {
	c.mu.Lock()
	deadline := c.writeDeadline
	if read {
		deadline = c.readDeadline
	}
	changed := c.changed
	c.mu.Unlock()
	if deadline.IsZero() {
		return nil, changed, func() {}
	}
	timer := time.NewTimer(max(time.Until(deadline), 0))
	return timer.C, changed, func() { timer.Stop() }
}
func (c *conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}
		select {
		case data := <-c.in:
			c.pending = data
			continue
		default:
		}
		timeout, changed, stop := c.deadline(true)
		select {
		case data := <-c.in:
			c.pending = data
			stop()
		case <-c.peer.done:
			stop()
			select {
			case data := <-c.in:
				c.pending = data
			default:
				return 0, io.EOF
			}
		case <-c.done:
			stop()
			return 0, net.ErrClosed
		case <-changed:
			stop()
		case <-timeout:
			stop()
			return 0, os.ErrDeadlineExceeded
		}
	}
}
func (c *conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		select {
		case <-c.done:
			return written, net.ErrClosed
		case <-c.peer.done:
			return written, io.ErrClosedPipe
		default:
		}
		n := min(len(p), 32768)
		data := append([]byte(nil), p[:n]...)
		timeout, changed, stop := c.deadline(false)
		select {
		case c.peer.in <- data:
			written += n
			p = p[n:]
			stop()
		case <-c.done:
			stop()
			return written, net.ErrClosed
		case <-c.peer.done:
			stop()
			return written, io.ErrClosedPipe
		case <-changed:
			stop()
		case <-timeout:
			stop()
			return written, os.ErrDeadlineExceeded
		}
	}
	return written, nil
}
func (c *conn) Close() error         { c.once.Do(func() { close(c.done) }); return nil }
func (c *conn) LocalAddr() net.Addr  { return address("127.0.0.1:2200") }
func (c *conn) RemoteAddr() net.Addr { return address("127.0.0.1:2201") }
func (c *conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}
func (c *conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}
func (c *conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}

type address string

func (a address) Network() string { return "tcp" }
func (a address) String() string  { return string(a) }

type Listener struct {
	incoming chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func NewListener() *Listener {
	return &Listener{incoming: make(chan net.Conn), done: make(chan struct{})}
}
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *Listener) Dial() (net.Conn, error) {
	a, b := Pair()
	select {
	case l.incoming <- b:
		return a, nil
	case <-l.done:
		_ = a.Close()
		_ = b.Close()
		return nil, net.ErrClosed
	}
}
func (l *Listener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *Listener) Addr() net.Addr { return address("127.0.0.1:443") }
