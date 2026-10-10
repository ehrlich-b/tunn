package sshfront

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/testnet"
)

type edgeObservedConn struct {
	net.Conn
	reading chan struct{}
	once    sync.Once
}

func (c *edgeObservedConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(p)
}

type edgeObservedListener struct {
	*testnet.Listener
	accepted chan *edgeObservedConn
}

func (l *edgeObservedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	observed := &edgeObservedConn{Conn: c, reading: make(chan struct{})}
	l.accepted <- observed
	return observed, nil
}

func TestEdgeSniffShutdownClosesUnclassifiedConnections(t *testing.T) {
	for _, prefix := range []string{"", "S", "SSH-2.0"} {
		t.Run(fmt.Sprintf("prefix=%q", prefix), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			listener := &edgeObservedListener{Listener: testnet.NewListener(), accepted: make(chan *edgeObservedConn, 1)}
			shared := Share(ctx, listener, func(context.Context, net.Conn) { t.Error("incomplete banner dispatched") })
			defer shared.Close()
			raw, err := listener.Dial()
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			if prefix != "" {
				if _, err := io.WriteString(raw, prefix); err != nil {
					t.Fatal(err)
				}
			}
			observed := <-listener.accepted
			select {
			case <-observed.reading:
			case <-time.After(time.Second):
				t.Fatal("classification did not start")
			}
			cancel()
			_ = raw.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := raw.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("shutdown retained unclassified connection: %v", err)
			}
			if _, err := shared.Accept(); err != net.ErrClosed {
				t.Fatalf("Accept after shutdown=%v", err)
			}
		})
	}
}
