package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func waitTCP(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("TCP worker did not reach synchronization point")
	}
}

func TestTCPOriginHalfClosePreservesDelayedUpload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	originDone := make(chan struct{})
	originResult := make(chan error, 1)
	go func() {
		defer close(originDone)
		conn, err := listener.Accept()
		if err != nil {
			originResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Write([]byte("response-before-upload"))
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		if err == nil {
			var body []byte
			body, err = io.ReadAll(conn)
			if err == nil && string(body) != "delayed-upload" {
				err = fmt.Errorf("origin received %q, want delayed-upload", body)
			}
		}
		originResult <- err
	}()

	ctx, cancel := context.WithCancel(context.Background())
	manager := newInboundConnectionManager()
	defer func() { cancel(); manager.closeAll(io.EOF); manager.workers.Wait(); waitTCP(t, originDone) }()
	halfClosed := make(chan struct{})
	var response []byte
	sender := durableLeaseSender{sent: func(msg *pb.TunnelMessage) error {
		if data := msg.GetConnectionData(); data != nil {
			response = append(response, data.Data...)
		}
		if msg.GetConnectionHalfClose() != nil {
			close(halfClosed)
		}
		return nil
	}}
	client := &ServeClient{TargetURL: listener.Addr().String(), EndpointProtocol: "tcp"}
	client.Inspector = NewInspector(client)
	manager.open(ctx, client, sender, &pb.ConnectionOpen{ConnectionId: "origin-first", Protocol: "tcp"})
	waitTCP(t, halfClosed)
	if string(response) != "response-before-upload" {
		t.Fatalf("response = %q", response)
	}
	joined := make(chan struct{})
	go func() { manager.workers.Wait(); close(joined) }()
	// Keep the upload open after observing the origin's EOF. Completing here
	// would discard later ConnectionData and release the admission too early.
	select {
	case <-joined:
		t.Fatal("origin half-close tore down the active upload")
	case <-time.After(25 * time.Millisecond):
	}
	if manager.get("origin-first") == nil || len(manager.slots) != 1 {
		t.Fatal("origin half-close released the active connection")
	}
	manager.write("origin-first", []byte("delayed-upload"))
	manager.halfClose("origin-first")
	waitTCP(t, originDone)
	if err := <-originResult; err != nil {
		t.Fatal(err)
	}
	waitTCP(t, joined)
	if manager.get("origin-first") != nil || len(manager.slots) != 0 {
		t.Fatal("completed connection retained its admission")
	}
}

// Hold a socket write after cancellation has unblocked it, so joining the
// upload is observable independently of the download handler's return.
type heldTCPWrite struct {
	net.Conn
	started, unblocked, release, returned chan struct{}
	readStarted                           chan struct{}
	readOnce                              sync.Once
}

func (c *heldTCPWrite) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	return c.Conn.Read(p)
}

func (c *heldTCPWrite) Write(p []byte) (int, error) {
	close(c.started)
	n, err := c.Conn.Write(p)
	close(c.unblocked)
	<-c.release
	close(c.returned)
	return n, err
}

func TestTCPCancelAndRevokeJoinBothPumps(t *testing.T) {
	for _, action := range []string{"cancel", "revoke", "shutdown"} {
		t.Run(action, func(t *testing.T) {
			local, peer := net.Pipe()
			defer peer.Close()
			conn := &heldTCPWrite{Conn: local, started: make(chan struct{}), unblocked: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{}), readStarted: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			manager := newInboundConnectionManager()
			release := sync.OnceFunc(func() { close(conn.release) })
			defer func() { release(); cancel(); manager.closeAll(io.EOF); manager.workers.Wait() }()
			client := &ServeClient{EndpointProtocol: "tcp", DialContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil }}
			manager.open(ctx, client, &mockEstablishTunnelClient{}, &pb.ConnectionOpen{ConnectionId: "blocked", Protocol: "tcp"})
			manager.write("blocked", []byte("upload"))
			waitTCP(t, conn.started)
			waitTCP(t, conn.readStarted)
			switch action {
			case "cancel":
				cancel()
			case "revoke":
				manager.close("blocked", "access revoked")
			case "shutdown":
				manager.closeAll(io.EOF)
			}
			waitTCP(t, conn.unblocked)
			joined := make(chan struct{})
			go func() { manager.workers.Wait(); close(joined) }()
			select {
			case <-joined:
				t.Fatal("connection workers joined while upload pump was still running")
			case <-time.After(25 * time.Millisecond):
			}
			release()
			waitTCP(t, conn.returned)
			waitTCP(t, joined)
			if manager.get("blocked") != nil || len(manager.slots) != 0 {
				t.Fatal("canceled connection retained its admission")
			}
		})
	}
}

type heldTCPRead struct {
	io.ReadCloser
	started, unblocked, release, returned chan struct{}
}

func (r *heldTCPRead) Read(p []byte) (int, error) {
	close(r.started)
	n, err := r.ReadCloser.Read(p)
	close(r.unblocked)
	<-r.release
	close(r.returned)
	return n, err
}

func TestTCPTerminationJoinsPendingInput(t *testing.T) {
	for _, action := range []string{"cancel-after-origin-eof", "relay-data-error", "relay-halfclose-error"} {
		t.Run(action, func(t *testing.T) {
			local, peer := net.Pipe()
			defer peer.Close()
			reader, writer := io.Pipe()
			defer writer.Close()
			input := &heldTCPRead{ReadCloser: reader, started: make(chan struct{}), unblocked: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{})}
			release := sync.OnceFunc(func() { close(input.release) })
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			defer func() { release(); cancel(); reader.Close(); local.Close(); waitTCP(t, done) }()
			client := &ServeClient{DialContext: func(context.Context, string, string) (net.Conn, error) { return local, nil }}
			// Inspection wraps the reader; cleanup must still close its pipe.
			client.Inspector = NewInspector(client)
			halfClosed := make(chan struct{})
			sender := durableLeaseSender{sent: func(msg *pb.TunnelMessage) error {
				if msg.GetConnectionHalfClose() != nil {
					close(halfClosed)
					if action == "relay-halfclose-error" {
						return errors.New("relay unavailable")
					}
				}
				if msg.GetConnectionData() != nil && action == "relay-data-error" {
					return errors.New("relay unavailable")
				}
				return nil
			}}
			go func() { client.handleStreamingTCP(ctx, sender, "pending-input", input); close(done) }()
			waitTCP(t, input.started)
			if action == "relay-data-error" {
				if _, err := peer.Write([]byte("response")); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = peer.Close()
				waitTCP(t, halfClosed)
				if action == "cancel-after-origin-eof" {
					cancel()
				}
			}
			waitTCP(t, input.unblocked)
			select {
			case <-done:
				t.Fatal("handler returned while input pump was still running")
			case <-time.After(25 * time.Millisecond):
			}
			release()
			waitTCP(t, input.returned)
			waitTCP(t, done)
		})
	}
}
