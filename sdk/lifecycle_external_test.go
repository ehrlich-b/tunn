package tunn_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	tunn "github.com/ehrlich-b/tunn/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type lifecycleRelay struct {
	pb.UnimplementedTunnelServiceServer
	run func(pb.TunnelService_EstablishTunnelServer) error
}

func (r *lifecycleRelay) EstablishTunnel(s pb.TunnelService_EstablishTunnelServer) error {
	return r.run(s)
}

func lifecycleFixture(t *testing.T, run func(pb.TunnelService_EstablishTunnelServer) error) tunn.Options {
	t.Helper()
	certServer := httptest.NewTLSServer(nil)
	t.Cleanup(certServer.Close)
	cert := certServer.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(certServer.Certificate())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})))
	pb.RegisterTunnelServiceServer(server, &lifecycleRelay{run: run})
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); listener.Close() })
	return tunn.Options{Origin: "http://127.0.0.1:1", ServerAddr: listener.Addr().String(), Name: "lifecycle", TLSConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12}, ConnectTimeout: 2 * time.Second, Reconnect: &tunn.ReconnectPolicy{MaxAttempts: 0}}
}
func register(s pb.TunnelService_EstablishTunnelServer, accept bool) error {
	m, err := s.Recv()
	if err != nil {
		return err
	}
	if m.GetRegisterClient() == nil {
		return errors.New("missing registration")
	}
	return s.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: accept, PublicUrl: "https://lifecycle.example.com", Capabilities: []string{"web-sharing-v1"}}}})
}
func drain(s pb.TunnelService_EstablishTunnelServer) error {
	for {
		if _, err := s.Recv(); err != nil {
			return err
		}
	}
}
func awaitDone(t *testing.T, p *tunn.Tunnel) {
	t.Helper()
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not close")
	}
	var last tunn.Event
	for e := range p.Events() {
		last = e
	}
	if last.State != tunn.Closed {
		t.Fatalf("last event: %+v", last)
	}
}
func channelsOpen(t *testing.T, p *tunn.Tunnel) {
	t.Helper()
	select {
	case <-p.Done():
		t.Fatal("Done closed unexpectedly")
	default:
	}
	for {
		select {
		case _, ok := <-p.Events():
			if !ok {
				t.Fatal("Events closed unexpectedly")
			}
		default:
			return
		}
	}
}
func ready(t *testing.T, p *tunn.Tunnel) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := p.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestLifecycleReference(t *testing.T) {
	t.Run("registration_rejection", func(t *testing.T) {
		o := lifecycleFixture(t, func(s pb.TunnelService_EstablishTunnelServer) error { return register(s, false) })
		p, err := tunn.Publish(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		awaitDone(t, p)
		var e *tunn.Error
		if _, err = p.WaitReady(context.Background()); !errors.As(err, &e) || e.Code != tunn.RegistrationRejected {
			t.Fatalf("WaitReady: %v", err)
		}
		if p.Close() != p.Wait() || p.Close() != p.Wait() {
			t.Fatal("failure not retained")
		}
	})
	t.Run("cancel_before_ready", func(t *testing.T) {
		entered := make(chan struct{})
		o := lifecycleFixture(t, func(s pb.TunnelService_EstablishTunnelServer) error {
			if _, err := s.Recv(); err != nil {
				return err
			}
			close(entered)
			return drain(s)
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p, err := tunn.Publish(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		<-entered
		cancel()
		awaitDone(t, p)
		if _, err = p.WaitReady(context.Background()); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if !errors.Is(p.Close(), context.Canceled) || !errors.Is(p.Close(), context.Canceled) {
			t.Fatal("cancellation not retained")
		}
	})
	t.Run("caller_timeout", func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		o := lifecycleFixture(t, func(s pb.TunnelService_EstablishTunnelServer) error {
			if _, err := s.Recv(); err != nil {
				return err
			}
			close(entered)
			select {
			case <-release:
			case <-s.Context().Done():
				return s.Context().Err()
			}
			if err := s.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://lifecycle.example.com", Capabilities: []string{"web-sharing-v1"}}}}); err != nil {
				return err
			}
			return drain(s)
		})
		p, err := tunn.Publish(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		<-entered
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if _, err = p.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		channelsOpen(t, p)
		close(release)
		readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer readyCancel()
		if url, err := p.WaitReady(readyCtx); err != nil || url != "https://lifecycle.example.com" {
			t.Fatalf("later readiness: %q %v", url, err)
		}
		if err = p.Close(); err != nil {
			t.Fatal(err)
		}
		awaitDone(t, p)
		if p.Close() != nil {
			t.Fatal("repeat Close")
		}
	})
	t.Run("origin_failure", func(t *testing.T) {
		result := make(chan int32, 1)
		o := lifecycleFixture(t, func(s pb.TunnelService_EstablishTunnelServer) error {
			if err := register(s, true); err != nil {
				return err
			}
			if err := s.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: "origin", Method: "GET", Path: "/"}}}); err != nil {
				return err
			}
			for {
				m, err := s.Recv()
				if err != nil {
					return err
				}
				if r := m.GetHttpResponse(); r != nil {
					result <- r.StatusCode
					return drain(s)
				}
			}
		})
		p, err := tunn.Publish(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		ready(t, p)
		select {
		case code := <-result:
			if code != 502 {
				t.Fatalf("status %d", code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no response")
		}
		channelsOpen(t, p)
		if err = p.Close(); err != nil {
			t.Fatal(err)
		}
		awaitDone(t, p)
		if p.Close() != nil {
			t.Fatal("repeat Close")
		}
	})
	t.Run("concurrent_close", func(t *testing.T) {
		o := lifecycleFixture(t, func(s pb.TunnelService_EstablishTunnelServer) error {
			if err := register(s, true); err != nil {
				return err
			}
			return drain(s)
		})
		p, err := tunn.Publish(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		ready(t, p)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := p.Close(); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		awaitDone(t, p)
		if url, err := p.WaitReady(context.Background()); err != nil || url != "https://lifecycle.example.com" {
			t.Fatalf("retained ready: %q %v", url, err)
		}
		if p.Close() != nil {
			t.Fatal("repeat Close")
		}
	})
}

func TestLifecycleTransientRegistration(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	o := lifecycleFixture(t, func(s pb.TunnelService_EstablishTunnelServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		mu.Lock()
		attempts++
		attempt := attempts
		mu.Unlock()
		if attempt == 1 {
			return s.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: false, ErrorMessage: "Web permission authority unavailable."}}})
		}
		if err := s.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://lifecycle.example.com", Capabilities: []string{"web-sharing-v1"}}}}); err != nil {
			return err
		}
		return drain(s)
	})
	o.Reconnect = nil
	p, err := tunn.Publish(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url, err := p.WaitReady(ctx)
	if err != nil || url != "https://lifecycle.example.com" {
		t.Fatalf("WaitReady: %q %v", url, err)
	}
	channelsOpen(t, p)
	mu.Lock()
	gotAttempts := attempts
	mu.Unlock()
	if gotAttempts != 2 {
		t.Fatalf("attempts: %d", gotAttempts)
	}
	closeErr := p.Close()
	waitErr := p.Wait()
	if closeErr != nil || waitErr != nil {
		t.Fatalf("Close: %v; Wait: %v", closeErr, waitErr)
	}
	t.Logf("rejected first registration; attempts=%d; WaitReady=%q, nil; Close=nil; Wait=nil", gotAttempts, url)
}

func TestLifecycleRejectedReconnect(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	allowDisconnect := make(chan struct{})
	o := lifecycleFixture(t, func(s pb.TunnelService_EstablishTunnelServer) error {
		mu.Lock()
		attempts++
		attempt := attempts
		mu.Unlock()
		if attempt == 1 {
			if err := register(s, true); err != nil {
				return err
			}
			<-allowDisconnect
			return nil
		}
		return register(s, false)
	})
	o.Reconnect = &tunn.ReconnectPolicy{MaxAttempts: 1, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}
	p, err := tunn.Publish(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ready(t, p)
	close(allowDisconnect)
	awaitDone(t, p)
	var terminal *tunn.Error
	if !errors.As(p.Wait(), &terminal) || terminal.Code != tunn.RegistrationRejected {
		t.Fatalf("terminal: %v", p.Wait())
	}
	url, err := p.WaitReady(context.Background())
	if err != nil || url != "https://lifecycle.example.com" {
		t.Fatalf("retained readiness: %q, %v", url, err)
	}
	if err := p.Close(); err != p.Wait() {
		t.Fatalf("Close: %v; Wait: %v", err, p.Wait())
	}
	t.Logf("second registration rejected; WaitReady=%q, nil; Wait=%v; Close=%v", url, p.Wait(), p.Close())
}
