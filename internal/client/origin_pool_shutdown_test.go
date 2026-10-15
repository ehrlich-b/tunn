package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestOriginPoolShutdownClosesUnretiredConnections(t *testing.T) {
	for _, late := range []bool{false, true} {
		name := "connected"
		if late {
			name = "dial-completes-after-shutdown"
		}
		t.Run(name, func(t *testing.T) {
			local, origin := net.Pipe()
			defer local.Close()
			defer origin.Close()
			entered, release := make(chan struct{}), make(chan struct{})
			client := &ServeClient{LocalDialContext: func(context.Context, string, string) (net.Conn, error) {
				close(entered)
				<-release
				return local, nil
			}}
			transport, closePool := client.originHTTPTransport(context.Background())
			defer closePool()
			type result struct {
				conn net.Conn
				err  error
			}
			done := make(chan result, 1)
			go func() {
				conn, err := transport.(*http.Transport).DialContext(context.Background(), "tcp", "origin.test:80")
				done <- result{conn, err}
			}()
			<-entered
			if late {
				closePool()
			}
			close(release)
			got := <-done
			if late {
				if got.conn != nil || !errors.Is(got.err, net.ErrClosed) {
					t.Errorf("late dial = (%v, %v), want a closed pool error", got.conn, got.err)
				}
			} else {
				if got.err != nil {
					t.Fatal(got.err)
				}
				// The socket has not entered the transport's idle list. HTTP/2
				// stream retirement can likewise lag the request worker's exit.
				closePool()
			}
			_ = origin.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := origin.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("publisher socket remained open after shutdown: %v", err)
			}
		})
	}
}
