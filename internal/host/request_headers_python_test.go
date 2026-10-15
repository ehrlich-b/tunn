//go:build pythonsdk

package host

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

func TestPythonSDKRepeatedRequestHeaders(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		for _, mode := range []string{"sync-origin", "async-origin"} {
			wire := "streamed"
			if buffered {
				wire = "buffered"
			}
			t.Run(mode+"/"+wire, func(t *testing.T) {
				cfg := &config.Config{ClientSecret: "request-python-fixture", Domain: "tunn.test", JWTSecret: "request-cookie-fixture", NodeSecret: "request-node-fixture"}
				server := NewTunnelServer(cfg, nil, nil, nil)
				var implementation pb.TunnelServiceServer = server
				if buffered {
					implementation = &sdkBufferedRelay{server}
				}
				gs := grpc.NewServer()
				pb.RegisterTunnelServiceServer(gs, implementation)
				proxy := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: server, grpcServer: gs, storage: storage.NewProxyStorage(), quotaCache: NewQuotaCache(time.Minute)}
				relay := httptest.NewUnstartedServer(proxy.createHTTP2Router(http.HandlerFunc(proxy.handleWebProxy)))
				relay.EnableHTTP2 = true
				relay.StartTLS()
				t.Cleanup(func() { gs.Stop(); relay.Close() })
				origin := httptest.NewServer(requestHeadersOrigin(t))
				defer origin.Close()
				ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: relay.Certificate().Raw}))
				consumer := startPythonConsumer(t, map[string]any{"mode": mode, "origin": origin.URL, "server_addr": relay.Listener.Addr().String(), "ca_pem": ca, "credentials": map[string]string{"auth_token": cfg.ClientSecret, "endpoint_token": sdkEndpointToken}, "allowed_emails": []string{"alice@example.com"}})
				if ready := consumer.read(t); ready["phase"] != "ready" {
					t.Fatalf("not ready: %v", ready)
				}
				request, _ := http.NewRequest("GET", relay.URL+"/headers", nil)
				request.Host = "websocket-fixture.tunn.test"
				request.Header = http.Header{"X-App": {"first, literal", "second"}, "Cookie": {"a=1", "tunn_auth=secret; b=2"}, "Authorization": {"Bearer application"}, "Tunn-Authorization": {"Bearer " + sdkEndpointToken}, "Connection": {"X-Hop"}, "X-Hop": {"secret"}}
				transport := relay.Client().Transport.(*http.Transport).Clone()
				transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
				transport.Protocols = new(http.Protocols)
				transport.Protocols.SetHTTP1(true)
				defer transport.CloseIdleConnections()
				response, err := (&http.Client{Transport: transport}).Do(request)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != 204 {
					t.Fatalf("status %d", response.StatusCode)
				}
				pythonClose(t, consumer, "close")
			})
		}
	}
}
