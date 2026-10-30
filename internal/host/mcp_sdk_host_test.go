package host

import (
	"context"
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
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestMCPGoSDKHostThroughTunnel(t *testing.T) {
	for _, rewrite := range []bool{true, false} {
		t.Run(map[bool]string{true: "default", false: "keep-original"}[rewrite], func(t *testing.T) {
			sdk := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
			mcp.AddTool(sdk, &mcp.Tool{Name: "echo"}, func(ctx context.Context, req *mcp.CallToolRequest, args struct {
				Text string `json:"text"`
			}) (*mcp.CallToolResult, any, error) { return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: args.Text}}}, nil, nil })
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return sdk }, nil)
			local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Forwarded-Host") != "tools.tunn.test" {
					t.Errorf("forwarded host = %q", r.Header.Get("X-Forwarded-Host"))
				}
				handler.ServeHTTP(w, r)
			}))
			defer local.Close()
			certServer := httptest.NewTLSServer(http.NotFoundHandler())
			cert := certServer.TLS.Certificates[0]
			certServer.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			tunnelServer := NewTunnelServer(&config.Config{PublicMode: true, Domain: "tunn.test"}, nil, nil, nil)
			grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})))
			pb.RegisterTunnelServiceServer(grpcServer, tunnelServer)
			go grpcServer.Serve(listener)
			defer grpcServer.Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			publisher := &client.ServeClient{TunnelID: "integration", TargetURL: local.URL, PublicPath: "/mcp", UpstreamPath: "/mcp", RewriteMCPHost: rewrite, ServerAddr: listener.Addr().String(), Insecure: true, InitialDelay: time.Millisecond, MaxReconnectDelay: 10 * time.Millisecond}
			go publisher.Run(ctx)
			var tunnel *TunnelConnection
			for tunnel == nil && ctx.Err() == nil {
				tunnel, _ = tunnelServer.GetTunnel("integration")
				time.Sleep(time.Millisecond)
			}
			if tunnel == nil {
				t.Fatal("publisher did not register")
			}
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Host = "tools.tunn.test"
				r.Header.Set("X-Forwarded-Host", r.Host)
				if err := (&ProxyServer{}).proxyHTTPOverGRPC(w, r, tunnel); err != nil {
					t.Error(err)
				}
			}))
			defer relay.Close()
			if !rewrite {
				req, _ := http.NewRequest("POST", relay.URL+"/mcp", strings.NewReader(`{}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json, text/event-stream")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != 403 {
					t.Fatalf("status=%d body=%s", resp.StatusCode, b)
				}
				t.Log("public Host reproduces SDK 403")
				return
			}
			c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
			session, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: relay.URL + "/mcp", DisableStandaloneSSE: true, MaxRetries: -1}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hello"}})
			if err != nil || result.IsError || len(result.Content) != 1 || result.Content[0].(*mcp.TextContent).Text != "hello" {
				t.Fatalf("tool result=%v err=%v", result, err)
			}
			t.Log("SDK tool call succeeded through gRPC tunnel")
		})
	}
}
