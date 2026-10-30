package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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

func TestMCPPythonSDKHostThroughTunnel(t *testing.T) {
	python := os.Getenv("TUNN_MCP_PYTHON")
	if python == "" {
		t.Skip("set TUNN_MCP_PYTHON to a Python environment with the MCP SDK")
	}
	for _, rewrite := range []bool{true, false} {
		t.Run(map[bool]string{true: "default", false: "keep-original"}[rewrite], func(t *testing.T) {
			process := exec.Command(python, "testdata/mcp_python_server.py")
			stdout, err := process.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = process.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
			scanner := bufio.NewScanner(stdout)
			if !scanner.Scan() {
				t.Fatal("Python SDK did not provide its URL")
			}
			localURL := scanner.Text()
			deadline := time.Now().Add(5 * time.Second)
			for {
				c, err := net.DialTimeout("tcp", strings.TrimPrefix(localURL, "http://"), time.Second)
				if err == nil {
					_ = c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal(err)
				}
				time.Sleep(10 * time.Millisecond)
			}
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
			publisher := &client.ServeClient{TunnelID: "integration", TargetURL: localURL, PublicPath: "/mcp", UpstreamPath: "/mcp", RewriteMCPHost: rewrite, ServerAddr: listener.Addr().String(), Insecure: true, InitialDelay: time.Millisecond, MaxReconnectDelay: 10 * time.Millisecond}
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
				if resp.StatusCode != 421 {
					t.Fatalf("status=%d body=%s", resp.StatusCode, b)
				}
				t.Logf("Python SDK public Host denied: status=%d body=%s", resp.StatusCode, b)
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
			t.Log("Python SDK echo tool succeeded through gRPC tunnel")
		})
	}
}
