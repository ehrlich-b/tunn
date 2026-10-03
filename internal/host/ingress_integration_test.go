package host

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// A loopback publisher, TLS gRPC transport, a second HTTP routing node and
// authenticated login-node RPC exercise both transport paths without live ingress.
func TestIngressAcrossRealGRPCTunnel(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{false: "buffered", true: "streaming"}[streaming], func(t *testing.T) {
			db, err := store.InitForTest()
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			defer db.Close()
			local := storage.NewLocalStorage(db)
			account, err := local.FindOrCreateByEmails(context.Background(), []string{"public@tunn.local"}, "github")
			if err != nil {
				t.Fatal(err)
			}
			remote := ingressProxyStorage(t, local)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Tunn-Authorization") != "" || strings.Contains(r.Header.Get("Cookie"), authCookieName) {
					t.Error("platform credential reached target")
				}
				if r.Header.Get("Authorization") != "Bearer upstream-only" {
					t.Error("upstream authorization not preserved")
				}
				if r.URL.RequestURI() != "/api/usage?secret=local-only" {
					t.Errorf("URI=%s", r.URL.RequestURI())
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write(append([]byte("ok:"), body...))
			}))
			defer target.Close()
			certSource := httptest.NewTLSServer(http.NotFoundHandler())
			cert := certSource.TLS.Certificates[0]
			certSource.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			cfg := &config.Config{PublicMode: true, Domain: "tunn.test", JWTSecret: "synthetic-signing-key", Insecure: true}
			ts := NewTunnelServer(cfg, nil, nil, remote)
			gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})))
			pb.RegisterTunnelServiceServer(gs, ts)
			go func() { _ = gs.Serve(listener) }()
			defer gs.Stop()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			token := "synthetic-integration-token"
			digest := sha256.Sum256([]byte(token))
			publisher := &client.ServeClient{TunnelID: "integration", TargetURL: target.URL, ServerAddr: listener.Addr().String(), Insecure: true, InitialDelay: time.Millisecond, MaxReconnectDelay: 10 * time.Millisecond, AllowedEmails: []string{"alice@example.test"}, AccessTokenSHA256: digest[:]}
			done := make(chan error, 1)
			go func() { done <- publisher.Run(ctx) }()
			var tunnel *TunnelConnection
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if found, ok := ts.GetTunnel("integration"); ok {
					tunnel = found
					break
				}
				time.Sleep(time.Millisecond)
			}
			if tunnel == nil {
				t.Fatal("publisher did not register")
			}
			if tunnel.AccountID != account.ID || tunnel.TargetURL != "http" {
				t.Fatalf("registration=%+v", tunnel)
			}
			if !streaming {
				tunnel.Capabilities = nil
			}
			owner := &ProxyServer{Domain: cfg.Domain, config: cfg, storage: remote, tunnelServer: ts, usageBuffer: NewUsageBuffer(), quotaCache: NewQuotaCache(time.Second)}
			host := httptest.NewTLSServer(owner.createHandler())
			defer host.Close()
			routing := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil), tunnelCache: map[string]string{"integration": strings.TrimPrefix(host.URL, "https://")}}
			ingress := httptest.NewTLSServer(routing.createHandler())
			defer ingress.Close()
			req, err := http.NewRequest(http.MethodPost, ingress.URL+"/api/usage?secret=local-only", strings.NewReader("request"))
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "integration.tunn.test"
			req.Header.Set("Tunn-Authorization", "Bearer "+token)
			req.Header.Set("Authorization", "Bearer upstream-only")
			req.Header.Set("X-Tunn-Caller", "forged")
			response, err := ingress.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 || string(body) != "ok:request" {
				t.Fatalf("HTTP=%d %s", response.StatusCode, body)
			}
			// Recording finishes before the handler returns; poll only for HTTP flush timing.
			var out *store.IngressExport
			deadline = time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				out = exportIngress(t, remote, account.ID, false)
				if len(out.Events) == 1 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if len(out.Events) != 1 {
				t.Fatalf("routing double counted or lost: %+v", out)
			}
			event := out.Events[0]
			if event.CallerID != "endpoint-token" || event.RequestBytes != 7 || event.ResponseBytes != 10 || !event.Forwarded || event.Outcome != "completed" {
				t.Fatalf("event=%+v", event)
			}
			usage, err := remote.GetMonthlyUsage(context.Background(), account.ID)
			if err != nil || usage != 17 {
				t.Fatalf("owner usage=%d %v", usage, err)
			}
			// An actual unauthenticated request is recorded but cannot reach the target.
			deniedReq, err := http.NewRequest(http.MethodPost, ingress.URL+"/mcp", strings.NewReader("denied-body"))
			if err != nil {
				t.Fatal(err)
			}
			deniedReq.Host = "integration.tunn.test"
			denied, err := ingress.Client().Do(deniedReq)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, denied.Body)
			denied.Body.Close()
			if denied.StatusCode != 401 {
				t.Fatalf("denied=%d", denied.StatusCode)
			}
			counters := exportIngress(t, remote, account.ID, true)
			if len(counters.Counters) != 2 {
				t.Fatalf("counters=%+v", counters)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("publisher failed to stop")
			}
		})
	}
}
