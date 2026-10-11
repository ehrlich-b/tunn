package sshfront

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/testnet"
)

func TestEdgeSniffFragmentedBytesRemainIntact(t *testing.T) {
	for _, payload := range [][]byte{[]byte("SSH-2.0-client with-comment\r\n"), {0x16, 3, 1, 0, 4, 1, 2, 3, 4}} {
		for seed := int64(0); seed < 8; seed++ {
			t.Run(fmt.Sprintf("first=%02x/seed=%d", payload[0], seed), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				listener := testnet.NewListener()
				received := make(chan []byte, 1)
				read := func(c net.Conn) {
					defer func() { _ = c.Close() }()
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					data := make([]byte, len(payload))
					if _, err := io.ReadFull(c, data); err != nil {
						t.Error(err)
					}
					received <- data
				}
				shared := Share(ctx, listener, func(_ context.Context, c net.Conn) { read(c) })
				defer func() { _ = shared.Close() }()
				if payload[0] == 0x16 {
					go func() {
						c, err := shared.Accept()
						if err != nil {
							t.Error(err)
							return
						}
						read(c)
					}()
				}
				raw, err := listener.Dial()
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = raw.Close() }()
				_ = raw.SetWriteDeadline(time.Now().Add(2 * time.Second))
				rng := rand.New(rand.NewSource(seed))
				for offset := 0; offset < len(payload); {
					n := min(1+rng.Intn(4), len(payload)-offset)
					if _, err := raw.Write(payload[offset : offset+n]); err != nil {
						t.Fatal(err)
					}
					offset += n
				}
				select {
				case data := <-received:
					if !bytes.Equal(data, payload) {
						t.Fatalf("classification changed bytes: %x != %x", data, payload)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("fragmented protocol was not dispatched")
				}
			})
		}
	}
}

func TestEdgeSniffRejectsUnsupportedProtocols(t *testing.T) {
	for _, payload := range []string{"GET / HTTP/1.1\r\n\r\n", "SSH-1.5-old\r\n", "SSH-2.1-client\r\n", "STARTTLS\r\n", "\x15\x03\x03\x00\x00"} {
		t.Run(fmt.Sprintf("payload=%q", payload), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			listener := testnet.NewListener()
			shared := Share(ctx, listener, func(_ context.Context, c net.Conn) {
				defer func() { _ = c.Close() }()
				t.Error("unsupported protocol dispatched to SSH")
			})
			defer func() { _ = shared.Close() }()
			raw, err := listener.Dial()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = raw.Close() }()
			if _, err := io.WriteString(raw, payload); err != nil {
				t.Fatal(err)
			}
			_ = raw.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := raw.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("unsupported protocol did not close: %v", err)
			}
		})
	}
}
