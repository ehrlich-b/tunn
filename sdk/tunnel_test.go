package tunn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type fixtureRelay struct {
	pb.UnimplementedTunnelServiceServer
	handle func(pb.TunnelService_EstablishTunnelServer) error
}

func (f *fixtureRelay) EstablishTunnel(stream pb.TunnelService_EstablishTunnelServer) error {
	return f.handle(stream)
}

func fixtureTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SDK fixture"}, DNSNames: []string{"sdk.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, &tls.Config{RootCAs: pool, ServerName: "sdk.test", MinVersion: tls.VersionTLS12}
}

func startFixture(t *testing.T, handle func(pb.TunnelService_EstablishTunnelServer) error) (func(context.Context, string, string) (net.Conn, error), *tls.Config) {
	t.Helper()
	serverTLS, clientTLS := fixtureTLS(t)
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	pb.RegisterTunnelServiceServer(server, &fixtureRelay{handle: handle})
	served := make(chan struct{})
	go func() { defer close(served); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close(); <-served })
	return func(ctx context.Context, _, _ string) (net.Conn, error) { return listener.DialContext(ctx) }, clientTLS
}

func fixtureOptions() Options {
	return Options{Origin: "http://fixture.invalid", ServerAddr: "127.0.0.1:10443", ConnectTimeout: time.Second, Reconnect: &ReconnectPolicy{MaxAttempts: 0}}
}

func startFixtureTunnel(t *testing.T, ctx context.Context, o Options, dial func(context.Context, string, string) (net.Conn, error), origin *handlerOrigin) *Tunnel {
	t.Helper()
	core, name, err := publisher(o)
	if err != nil {
		t.Fatal(err)
	}
	core.DialContext = dial
	tunnel, err := startTunnel(ctx, o, core, name, origin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Close() })
	return tunnel
}

func registration(stream pb.TunnelService_EstablishTunnelServer) (*pb.RegisterClient, error) {
	message, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	reg := message.GetRegisterClient()
	if reg == nil {
		return nil, errors.New("missing registration")
	}
	return reg, nil
}

func acceptRegistration(stream pb.TunnelService_EstablishTunnelServer, reg *pb.RegisterClient) error {
	return stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://" + reg.TunnelId + ".sdk.test", Capabilities: []string{"web-sharing-v1", "http-stream-v1", "connection-stream-v1", "websocket-v1", "http-response-trailers-v1"}}}})
}

func drainUntilCanceled(stream pb.TunnelService_EstablishTunnelServer) error {
	for {
		if _, err := stream.Recv(); err != nil {
			return err
		}
	}
}

func waitDone(t *testing.T, tunnel *Tunnel) {
	t.Helper()
	select {
	case <-tunnel.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not stop")
	}
}

func collectEvents(t *testing.T, tunnel *Tunnel) []Event {
	t.Helper()
	waitDone(t, tunnel)
	var events []Event
	closed := 0
	for event := range tunnel.Events() {
		events = append(events, event)
		if event.State == Closed {
			closed++
		}
	}
	if closed != 1 || len(events) == 0 || events[len(events)-1].State != Closed {
		t.Fatalf("terminal event count/order: %v", events)
	}
	if len(events) > eventCapacity {
		t.Fatalf("unbounded event stream: %d", len(events))
	}
	return events
}

func TestSDKReadyAndConcurrentClose(t *testing.T) {
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
		reg, err := registration(stream)
		if err != nil {
			return err
		}
		if err := acceptRegistration(stream, reg); err != nil {
			return err
		}
		return drainUntilCanceled(stream)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o := fixtureOptions()
	o.TLSConfig = tlsConfig
	tunnel := startFixtureTunnel(t, ctx, o, dial, nil)
	waitCtx, waitCancel := context.WithTimeout(ctx, 2*time.Second)
	defer waitCancel()
	url, err := tunnel.WaitReady(waitCtx)
	if err != nil || url != "https://"+tunnel.Name()+".sdk.test" {
		t.Fatalf("readiness: %s %v", url, err)
	}
	var callers sync.WaitGroup
	for range 16 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if err := tunnel.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	callers.Wait()
	if ctx.Err() != nil {
		t.Fatal("Close canceled caller's context")
	}
	if tunnel.Wait() != nil || tunnel.Status().State != Closed {
		t.Fatalf("terminal result: %v %v", tunnel.Wait(), tunnel.Status())
	}
	events := collectEvents(t, tunnel)
	if len(events) != 3 || events[0].State != Connecting || events[1].State != Ready {
		t.Fatalf("ready ordering: %v", events)
	}
	if retained, err := tunnel.WaitReady(context.Background()); err != nil || retained != url {
		t.Fatalf("lost retained ready result: %s %v", retained, err)
	}
}

func TestSDKRegistrationFailureAndCredentialRedaction(t *testing.T) {
	const secret = "credential-sentinel-sdk-123456789"
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
		reg, err := registration(stream)
		if err != nil {
			return err
		}
		if reg.AuthToken != secret || reg.TunnelKey != secret || reg.TargetUrl != "http" {
			return errors.New("registration semantics changed")
		}
		return stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{ErrorMessage: secret}}})
	})
	var logs bytes.Buffer
	o := fixtureOptions()
	o.TLSConfig = tlsConfig
	o.Credentials = Credentials{AuthToken: secret, TunnelKey: secret}
	o.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	before := slog.Default()
	tunnel := startFixtureTunnel(t, context.Background(), o, dial, nil)
	events := collectEvents(t, tunnel)
	if len(events) != 3 || events[0].State != Connecting || events[1].State != Failed {
		t.Fatalf("error ordering: %v", events)
	}
	var public *Error
	if !errors.As(tunnel.Wait(), &public) || public.Code != RegistrationRejected {
		t.Fatalf("failure category: %v", tunnel.Wait())
	}
	for range 3 {
		if tunnel.Wait() != events[len(events)-1].Err {
			t.Fatal("lost terminal result")
		}
		if tunnel.Close() != tunnel.Wait() {
			t.Fatal("Close replaced a completed initialization failure")
		}
	}
	if strings.Contains(fmt.Sprintf("%+v %#v %v %s", events, o.Credentials, tunnel.Wait(), logs.String()), secret) {
		t.Fatal("credential sentinel leaked")
	}
	if slog.Default() != before {
		t.Fatal("SDK changed global logger")
	}
	if _, err := tunnel.WaitReady(context.Background()); err != tunnel.Wait() {
		t.Fatal("WaitReady lost initialization error")
	}
}

func TestSDKCancellationStages(t *testing.T) {
	for _, stage := range []string{"connect", "registration", "ready", "reconnect"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{}, 1)
			dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
				reg, err := registration(stream)
				if err != nil {
					return err
				}
				if stage == "registration" {
					entered <- struct{}{}
					return drainUntilCanceled(stream)
				}
				if err := acceptRegistration(stream, reg); err != nil {
					return err
				}
				if stage == "reconnect" {
					return status.Error(codes.Unavailable, "fixture disconnected")
				}
				return drainUntilCanceled(stream)
			})
			if stage == "connect" {
				dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					entered <- struct{}{}
					<-ctx.Done()
					return nil, ctx.Err()
				}
			}
			o := fixtureOptions()
			o.TLSConfig = tlsConfig
			o.Reconnect = &ReconnectPolicy{MaxAttempts: 2, InitialDelay: time.Second, MaxDelay: time.Second}
			tunnel := startFixtureTunnel(t, ctx, o, dial, nil)
			switch stage {
			case "connect", "registration":
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("stage not reached")
				}
			case "ready":
				waitCtx, stop := context.WithTimeout(ctx, 2*time.Second)
				defer stop()
				if _, err := tunnel.WaitReady(waitCtx); err != nil {
					t.Fatal(err)
				}
			case "reconnect":
				for {
					select {
					case event := <-tunnel.Events():
						if event.State == Reconnecting {
							goto reached
						}
					case <-time.After(2 * time.Second):
						t.Fatal("reconnect not reached")
					}
				}
			reached:
			}
			cancel()
			events := collectEvents(t, tunnel)
			if !errors.Is(tunnel.Wait(), context.Canceled) || !errors.Is(events[len(events)-1].Err, context.Canceled) {
				t.Fatalf("cancellation result: %v %v", tunnel.Wait(), events)
			}
		})
	}
}

func TestSDKReconnectIdentityAndBoundedEvents(t *testing.T) {
	var attempts atomic.Int32
	var identityMu sync.Mutex
	identity := ""
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
		reg, err := registration(stream)
		if err != nil {
			return err
		}
		identityMu.Lock()
		if identity == "" {
			identity = reg.TunnelId
		}
		same := identity == reg.TunnelId
		identityMu.Unlock()
		if !same {
			return errors.New("identity changed")
		}
		attempts.Add(1)
		if err := acceptRegistration(stream, reg); err != nil {
			return err
		}
		return status.Error(codes.Unavailable, "bounded functional retry fixture")
	})
	o := fixtureOptions()
	o.TLSConfig = tlsConfig
	o.Reconnect = &ReconnectPolicy{MaxAttempts: 20, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}
	tunnel := startFixtureTunnel(t, context.Background(), o, dial, nil)
	events := collectEvents(t, tunnel)
	if attempts.Load() != 21 {
		t.Fatalf("retry limit: %d", attempts.Load())
	}
	if len(events) != eventCapacity {
		t.Fatalf("expected bounded buffer saturation: %d", len(events))
	}
	if !errors.As(tunnel.Wait(), new(*Error)) {
		t.Fatalf("terminal connection error: %v", tunnel.Wait())
	}
	if tunnel.URL() != "https://"+tunnel.Name()+".sdk.test" {
		t.Fatal("identity URL not retained")
	}
	if _, err := tunnel.WaitReady(context.Background()); err != nil {
		t.Fatalf("ready result evicted with event queue: %v", err)
	}
}

func TestSDKProtocolResponses(t *testing.T) {
	for _, scenario := range []string{"duplicate", "wrong-first-message", "changed-url", "credential-url"} {
		t.Run(scenario, func(t *testing.T) {
			var attempts atomic.Int32
			dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
				reg, err := registration(stream)
				if err != nil {
					return err
				}
				n := attempts.Add(1)
				if scenario == "wrong-first-message" {
					return stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_HealthCheckResponse{HealthCheckResponse: &pb.HealthCheckResponse{}}})
				}
				if scenario == "credential-url" || scenario == "changed-url" && n == 2 {
					domain := "other.test"
					if scenario == "credential-url" {
						domain = "credential-sentinel-sdk.test"
					}
					return stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://" + reg.TunnelId + "." + domain, Capabilities: []string{"web-sharing-v1"}}}})
				}
				if err := acceptRegistration(stream, reg); err != nil {
					return err
				}
				if scenario == "duplicate" {
					return acceptRegistration(stream, reg)
				}
				return status.Error(codes.Unavailable, "fixture reconnect")
			})
			o := fixtureOptions()
			o.TLSConfig = tlsConfig
			o.Credentials.AuthToken = "credential-sentinel"
			o.Reconnect = &ReconnectPolicy{MaxAttempts: 2, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}
			tunnel := startFixtureTunnel(t, context.Background(), o, dial, nil)
			events := collectEvents(t, tunnel)
			var failure *Error
			if !errors.As(tunnel.Wait(), &failure) || failure.Code != ProtocolViolation {
				t.Fatalf("protocol result: %v", tunnel.Wait())
			}
			if strings.Contains(fmt.Sprint(events), o.Credentials.AuthToken) {
				t.Fatal("remote URL leaked credential")
			}
			want := int32(1)
			if scenario == "changed-url" {
				want = 2
			}
			if attempts.Load() != want {
				t.Fatalf("permanent failure was retried: %d", attempts.Load())
			}
		})
	}
}

func TestSDKConnectTimeoutAndWaitDeadline(t *testing.T) {
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
		if _, err := registration(stream); err != nil {
			return err
		}
		return drainUntilCanceled(stream)
	})
	o := fixtureOptions()
	o.TLSConfig = tlsConfig
	o.ConnectTimeout = 100 * time.Millisecond
	tunnel := startFixtureTunnel(t, context.Background(), o, dial, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, err := tunnel.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait deadline: %v", err)
	}
	select {
	case <-tunnel.Done():
		t.Fatal("wait deadline canceled publisher")
	default:
	}
	collectEvents(t, tunnel)
	var failure *Error
	if !errors.As(tunnel.Wait(), &failure) || failure.Code != ConnectionFailed {
		t.Fatalf("finite initialization timeout: %v", tunnel.Wait())
	}
}

func TestSDKOptionsAndSnapshots(t *testing.T) {
	for _, edit := range []func(*Options){
		func(o *Options) { o.Origin = "http://credential-sentinel@localhost" }, func(o *Options) { o.Origin = "file:///path" }, func(o *Options) { o.Origin = "http://localhost/private" }, func(o *Options) { o.Name = "bad name" }, func(o *Options) { o.ServerAddr = "https://localhost" }, func(o *Options) { o.ConnectTimeout = -1 }, func(o *Options) { o.Reconnect = &ReconnectPolicy{MaxAttempts: -1} }, func(o *Options) { o.WebSocket = &WebSocketOptions{MaxMessageSize: 0} }, func(o *Options) { o.Credentials.EndpointToken = "credential-sentinel" },
	} {
		o := fixtureOptions()
		edit(&o)
		_, err := Publish(context.Background(), o)
		var failure *Error
		if !errors.As(err, &failure) || failure.Code != InvalidOptions || strings.Contains(err.Error(), "credential-sentinel") {
			t.Fatalf("invalid option result: %v", err)
		}
	}
	o := fixtureOptions()
	o.Name = "snapshot"
	o.AllowedEmails = []string{"alice@example.test"}
	o.TLSConfig = &tls.Config{ServerName: "before", RootCAs: x509.NewCertPool()}
	o.Reconnect = &ReconnectPolicy{MaxAttempts: 3}
	o.WebSocket = &WebSocketOptions{MaxMessageSize: 1024}
	core, _, err := publisher(o)
	if err != nil {
		t.Fatal(err)
	}
	o.AllowedEmails[0] = "changed"
	o.TLSConfig.ServerName = "after"
	o.Reconnect.MaxAttempts = 999
	o.WebSocket.MaxMessageSize = 999
	if core.AllowedEmails[0] != "alice@example.test" || core.RelayTLSConfig.ServerName != "before" || core.RelayTLSConfig.RootCAs == o.TLSConfig.RootCAs || *core.ReconnectLimit != 3 || core.WebSocket.MaxMessageSize != 1024 {
		t.Fatal("options were not snapshotted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Publish(ctx, fixtureOptions()); !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled: %v", err)
	}
	if _, err := PublishHandler(context.Background(), http.NotFoundHandler(), fixtureOptions()); err == nil {
		t.Fatal("handler accepted explicit origin")
	}
	if _, err := PublishHandler(context.Background(), nil, Options{}); err == nil {
		t.Fatal("nil handler accepted")
	}
	if _, err := Publish(nil, fixtureOptions()); err == nil { //nolint:staticcheck // Verify rejection of a nil context.
		t.Fatal("nil context accepted")
	}
}
