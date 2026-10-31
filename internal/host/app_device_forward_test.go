package host

import (
	"bufio"
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

func appDeviceForwardFixture(t *testing.T, f *appDeviceFixture) (*ProxyServer, *httptest.Server) {
	t.Helper()
	f.p.config.NodeSecret = "fixture-forward-node"
	var handlers sync.WaitGroup
	handler := f.p.createHandler()
	backend := appDeviceTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.Add(1)
		defer handlers.Done()
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(func() {
		// httptest stops tracking hijacked WebSocket connections. Join their
		// handlers before fixture storage closes and removes its directory.
		backend.Close()
		finished := make(chan struct{})
		go func() { handlers.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("forwarded handlers did not finish before storage teardown")
		}
	})
	ca := filepath.Join(t.TempDir(), "node-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := *f.p.config
	cfg.InternalCACert = ca
	cfg.Insecure = false
	listener := bufconn.Listen(1 << 20)
	t.Cleanup(func() { listener.Close() })
	g := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor(cfg.NodeSecret)))
	internalpb.RegisterInternalServiceServer(g, NewInternalServer(f.p.tunnelServer, backend.Listener.Addr().String(), false))
	go g.Serve(listener)
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///forward-fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, in, out any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoke(metadata.NewOutgoingContext(ctx, metadata.Pairs("x-node-secret", cfg.NodeSecret)), method, in, out, cc, opts...)
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	front := &ProxyServer{Domain: f.p.Domain, config: &cfg, tunnelServer: NewTunnelServer(&cfg, nil, nil, nil), storage: f.p.storage, meter: f.p.meter, appDevices: f.p.appDevices, domains: f.p.domains, nodeClients: map[string]internalpb.InternalServiceClient{"backend": internalpb.NewInternalServiceClient(conn)}, tunnelCache: map[string]string{f.tunnel.TunnelID: backend.Listener.Addr().String()}, quotaCache: NewQuotaCache(time.Minute), usageBuffer: NewUsageBuffer()}
	return front, backend
}

func TestAppDeviceActualForwardedStalledReadersRevokeWithinFiveSeconds(t *testing.T) {
	for _, ws := range []bool{false, true} {
		t.Run(strconv.FormatBool(ws), func(t *testing.T) {
			f := newAppDeviceFixture(t)
			d, token := f.enroll(t, nil)
			appDeviceIdleOrigin(t, f, token)
			front, _ := appDeviceForwardFixture(t, f)
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			client.SetReadDeadline(time.Now().Add(4 * time.Second))
			observed := &appDeviceObservedConn{Conn: server, blocked: make(chan struct{})}
			r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/events", nil)
			r.Header.Set("Tunn-Authorization", "Bearer "+token)
			var writer http.ResponseWriter = &appDevicePipeResponse{observed, make(http.Header)}
			if ws {
				r.URL.Path = "/socket"
				r.Header.Set("Authorization", "Bearer upstream-only")
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Sec-WebSocket-Version", "13")
				r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				writer = &pipeUpgradeWriter{httptest.NewRecorder(), observed}
			}
			done := make(chan time.Time, 1)
			go func() {
				defer func() { recover(); server.Close(); done <- time.Now() }()
				front.createHandler().ServeHTTP(writer, r)
			}()
			if ws {
				reader := bufio.NewReader(client)
				response, err := http.ReadResponse(reader, r)
				if err != nil || response.StatusCode != 101 {
					t.Fatal("forward WS admission", err)
				}
			} else {
				ready := make([]byte, len(": ready\n\n"))
				if _, err := io.ReadFull(client, ready); err != nil {
					t.Fatal("forward SSE admission", err)
				}
			}
			// A healthy forwarded stream survives the shared admission budget.
			select {
			case <-done:
				t.Fatal("admission budget shortened forwarded stream")
			case <-time.After(2200 * time.Millisecond):
			}
			observed.observe.Store(true)
			f.tunnel.pendingMu.RLock()
			var id string
			for key := range f.tunnel.pendingStreams {
				id = key
				break
			}
			f.tunnel.pendingMu.RUnlock()
			if id == "" {
				t.Fatal("no backend stream")
			}
			data := []byte("data: stall\n\n")
			if ws {
				data = fixtureFrame(1, true, false, []byte("one small frame"))
			}
			f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: data}}})
			select {
			case <-observed.blocked:
			case <-time.After(time.Second):
				t.Fatal("forwarded reader did not stall")
			}
			if _, err := f.p.appDevices.revoke(context.Background(), d.Host, d.Account, d.ID, true); err != nil {
				t.Fatal(err)
			}
			committed := time.Now()
			select {
			case closed := <-done:
				if closed.Sub(committed) > 5*time.Second {
					t.Fatal("forwarded cutoff exceeded")
				}
				t.Logf("actual-forward ws=%v cutoff_ms=%d", ws, closed.Sub(committed).Milliseconds())
			case <-time.After(5 * time.Second):
				t.Fatal("frontend survived committed revoke")
			}
		})
	}
}

type appDeviceStalledCharge struct {
	metering.Backend
	mu      sync.Mutex
	block   bool
	entered chan struct{}
	once    sync.Once
}

func (b *appDeviceStalledCharge) Sharing(ctx context.Context, in *mp.SharingRequest) (*mp.SharingResponse, error) {
	return b.Backend.(metering.SharingBackend).Sharing(ctx, in)
}
func (b *appDeviceStalledCharge) Charge(ctx context.Context, in *mp.ChargeRequest) (*mp.Decision, error) {
	b.mu.Lock()
	block := b.block
	b.mu.Unlock()
	if block {
		b.once.Do(func() { close(b.entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return b.Backend.Charge(ctx, in)
}
func TestAppDeviceStalledMeterChargeCannotDelayRevoke(t *testing.T) {
	for _, upload := range []bool{false, true} {
		t.Run(strconv.FormatBool(upload), func(t *testing.T) {
			f := newAppDeviceFixture(t)
			d, token := f.enroll(t, nil)
			appDeviceIdleOrigin(t, f, token)
			meter := &appDeviceStalledCharge{Backend: f.p.meter, entered: make(chan struct{})}
			f.p.meter = meter
			server := appDeviceTLSServer(t, f.p.createHandler())
			stream := appDeviceSSE(t, server, token)
			meter.mu.Lock()
			meter.block = true
			meter.mu.Unlock()
			if upload {
				r := httptest.NewRequest("POST", "https://"+appDeviceTestHost+"/upload", nil)
				s := newIngressMeter(f.p, f.tunnel)
				s.admitted = true
				s.event.RequestId = "fixture-cancelled-upload"
				ctx, cancel := context.WithCancel(context.WithValue(r.Context(), domainAppKey{}, true))
				done := make(chan error, 1)
				go func() { _, err := s.charge(ctx, true, len("one small body")); done <- err }()
				<-meter.entered
				started := time.Now()
				cancel()
				select {
				case err := <-done:
					if err == nil || time.Since(started) > time.Second {
						t.Fatal("cancelled upload charge delayed")
					}
				case <-time.After(time.Second):
					t.Fatal("upload charge ignored cancellation")
				}
				s.mu.Lock()
				if s.readRequestBytes != int64(len("one small body")) {
					t.Error("read upload bytes were erased")
				}
				s.mu.Unlock()
				stream.close()
				return
			}
			f.tunnel.pendingMu.RLock()
			var id string
			for key := range f.tunnel.pendingStreams {
				id = key
				break
			}
			f.tunnel.pendingMu.RUnlock()
			f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte("data: charge\n\n")}}})
			<-meter.entered
			if _, err := f.p.appDevices.revoke(context.Background(), d.Host, d.Account, d.ID, true); err != nil {
				t.Fatal(err)
			}
			committed := time.Now()
			select {
			case closed := <-stream.closed:
				if closed.Sub(committed) > 5*time.Second {
					t.Fatal("meter delayed cutoff")
				}
				t.Logf("stalled meter cutoff_ms=%d", closed.Sub(committed).Milliseconds())
			case <-time.After(5 * time.Second):
				t.Fatal("meter held SSE transport")
			}
		})
	}
}

func TestAppDeviceSharedAdmissionDeadlineRejectsForgedExtension(t *testing.T) {
	f := newAppDeviceFixture(t)
	f.p.config.NodeSecret = "fixture-node"
	r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
	r.Header.Set(appRelayDeadline, strconv.FormatInt(time.Now().Add(time.Hour).UnixMilli(), 10))
	r.Header.Set(appRelayAdmissionID, "untrusted")
	r.Header.Set(appRelayAdmissionSignature, "fake")
	if time.Until(f.p.appAdmissionDeadline(r)) > 2100*time.Millisecond {
		t.Fatal("caller extended deadline")
	}
	peer, proto := f.p.forwardingPeer(r)
	past := strconv.FormatInt(time.Now().Add(-time.Second).UnixMilli(), 10)
	r.Header.Set(appRelayDeadline, past)
	r.Header.Set(appRelayAdmissionSignature, f.p.appRelaySignature(r.Host, peer, proto, past, "untrusted", "request"))
	if time.Until(f.p.appAdmissionDeadline(r)) >= 0 {
		t.Fatal("authenticated hop reset expired budget")
	}
}

func TestAppDeviceCachedRemoteAdmissionTimeoutReturns503(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, token := f.enroll(t, nil)
	front, _ := appDeviceForwardFixture(t, f)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			<-release
		}
	}()
	front.tunnelCache[f.tunnel.TunnelID] = listener.Addr().String()
	server := appDeviceTLSServer(t, front.createHandler())
	server.Client().Timeout = 4 * time.Second
	req, _ := http.NewRequest("GET", server.URL+"/", nil)
	req.Host = appDeviceTestHost
	req.Header.Set("Tunn-Authorization", "Bearer "+token)
	started := time.Now()
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal("admission timeout lost 503", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 503 || time.Since(started) > 2500*time.Millisecond {
		t.Fatalf("cached admission=%d elapsed=%s", response.StatusCode, time.Since(started))
	}
}

func TestAppDeviceOfflineAuditUsesRemainingAdmissionBudget(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, token := f.enroll(t, nil)
	f.p.tunnelServer.mu.Lock()
	delete(f.p.tunnelServer.tunnels, f.tunnel.TunnelID)
	f.p.tunnelServer.mu.Unlock()
	f.p.meter = appDeviceHangingAdmit{f.p.meter, t}
	started := time.Now()
	w := appDeviceOpen(f.p, appDeviceTestHost, token, nil)
	if w.Code != 503 || time.Since(started) > 2500*time.Millisecond {
		t.Fatalf("offline audit=%d elapsed=%s", w.Code, time.Since(started))
	}
}

func TestAppDeviceForwardedSlowApplicationKeepsStreamLifetime(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, token := f.enroll(t, nil)
	appDeviceIdleOrigin(t, f, token)
	original := f.stream.hook
	f.stream.hook = func(m *pb.TunnelMessage) error {
		if m.GetConnectionOpen() != nil {
			time.Sleep(2200 * time.Millisecond)
		}
		return original(m)
	}
	front, _ := appDeviceForwardFixture(t, f)
	server := appDeviceTLSServer(t, front.createHandler())
	server.Client().Timeout = 5 * time.Second
	stream := appDeviceSSE(t, server, token)
	stream.close()
}

func (b *appDeviceStalledCharge) IPPolicy(ctx context.Context, in *mp.IPPolicyRequest) (*mp.IPPolicy, error) {
	return b.Backend.(metering.IPPolicyBackend).IPPolicy(ctx, in)
}
func (b *appDeviceStalledCharge) EndpointPolicy(ctx context.Context, in *mp.EndpointPolicyRequest) (*mp.EndpointPolicyResponse, error) {
	return b.Backend.(metering.PolicyBackend).EndpointPolicy(ctx, in)
}
