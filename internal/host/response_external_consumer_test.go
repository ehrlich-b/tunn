package host

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

// REQUIRED ordinary-host gate. The program imports only exported SDK symbols
// and standard library packages. Memory handler assertions are a separate gate
// and cannot substitute for this live relay/SDK/downstream path.
func TestSDKExternalResponseConsumer(t *testing.T) {
	binary := os.Getenv("TUNN_RESPONSE_CONSUMER_BINARY")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "response-consumer")
		buildContext, cancelBuild := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancelBuild()
		build := exec.CommandContext(buildContext, "make", "-j1", "build-sdk-response-consumer", "SDK_RESPONSE_CONSUMER_OUTPUT="+binary)
		build.Dir = "../.."
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build exported response consumer: %v\n%s", err, output)
		}
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("REQUIRED: consumer binary path must be absolute")
	}
	cfg := &config.Config{ClientSecret: "response-consumer-publisher-fixture", Domain: "tunn.test", JWTSecret: "response-consumer-jwt-fixture", NodeSecret: "response-consumer-node-fixture"}
	server := NewTunnelServer(cfg, nil, nil, nil)
	grpcServer := grpc.NewServer()
	pb.RegisterTunnelServiceServer(grpcServer, server)
	proxy := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: server, grpcServer: grpcServer, storage: storage.NewProxyStorage(), quotaCache: NewQuotaCache(time.Minute)}
	relay := httptest.NewUnstartedServer(proxy.createHTTP2Router(http.HandlerFunc(proxy.handleWebProxy)))
	relay.EnableHTTP2 = true
	relay.StartTLS()
	defer relay.Close()
	defer grpcServer.Stop()
	caFile := filepath.Join(t.TempDir(), "relay-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: relay.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-ca", caFile, "-consumer-origin", relay.URL)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TUNN_") {
			command.Env = append(command.Env, entry)
		}
	}
	// Response conformance uses an explicit endpoint credential under private defaults.
	command.Env = append(command.Env, "TUNN_SERVER_ADDR="+relay.Listener.Addr().String(), "TUNN_AUTH_TOKEN="+cfg.ClientSecret, "TUNN_ENDPOINT_TOKEN=tunn_ep_response-consumer-fixture")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("external SDK response consumer: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "PASS: 2 cookies; streamed prefix and suffix; 2 terminal trailers; 1 SDK Closed event") {
		t.Fatalf("external consumer did not validate its response: %s", output)
	}
	t.Log(strings.TrimSpace(string(output)))
}
