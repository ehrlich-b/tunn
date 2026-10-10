package sshfront

import (
	"context"
	"github.com/ehrlich-b/tunn/internal/testnet"
	"io"
	"net"
	"testing"
	"time"
)

func TestSniffSSHAndTLS(t *testing.T) {
	l := testnet.NewListener()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 1)
	shared := Share(ctx, l, func(_ context.Context, c net.Conn) {
		defer func() { _ = c.Close() }()
		b := make([]byte, 8)
		_, e := io.ReadFull(c, b)
		if e == nil {
			got <- string(b)
		}
	})
	defer func() { _ = shared.Close() }()
	s, err := l.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	_, _ = s.Write([]byte("SSH-2.0-client\r\n"))
	select {
	case banner := <-got:
		if banner != "SSH-2.0-" {
			t.Fatal(banner)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH sniff timeout")
	}
	tls, err := l.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tls.Close() }()
	_, _ = tls.Write([]byte{0x16, 3, 1, 0, 1, 0})
	conn, err := shared.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	b := make([]byte, 6)
	if _, err := io.ReadFull(conn, b); err != nil {
		t.Fatal(err)
	}
	if b[0] != 0x16 || b[5] != 0 {
		t.Fatalf("ClientHello corrupted: %v", b)
	}
	cancel()
	if _, err := shared.Accept(); err == nil {
		t.Fatal("closed listener accepted")
	}
}
