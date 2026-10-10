package host

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestStreamingHTTPAcrossRealGRPCTunnel(t *testing.T) {
	localTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/events?client=one" {
			t.Errorf("local request URI = %q", r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: first\n\n"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("event: second\n\n"))
	}))
	defer localTarget.Close()

	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateSource.TLS.Certificates[0]
	certificateSource.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	tunnelServer := NewTunnelServer(&config.Config{
		PublicMode: true,
		Domain:     "tunn.test",
	}, nil, nil, nil)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
	})))
	pb.RegisterTunnelServiceServer(grpcServer, tunnelServer)
	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveClient := &client.ServeClient{
		TunnelID:          "integration",
		TargetURL:         localTarget.URL,
		ServerAddr:        listener.Addr().String(),
		Insecure:          true,
		InitialDelay:      5 * time.Millisecond,
		MaxReconnectDelay: 20 * time.Millisecond,
	}
	clientDone := make(chan error, 1)
	go func() { clientDone <- serveClient.Run(ctx) }()

	var tunnel *TunnelConnection
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if connected, exists := tunnelServer.GetTunnel("integration"); exists {
			tunnel = connected
			break
		}
		time.Sleep(time.Millisecond)
	}
	if tunnel == nil {
		cancel()
		t.Fatalf("publisher did not register: %v", <-clientDone)
	}
	if !tunnel.Supports("http-stream-v1") {
		t.Fatal("publisher did not negotiate streaming HTTP")
	}
	if tunnel.TargetURL != "http" {
		t.Fatalf("relay received unredacted target %q", tunnel.TargetURL)
	}

	request := httptest.NewRequest(http.MethodGet, "/events?client=one", nil)
	recorder := httptest.NewRecorder()
	if err := (&ProxyServer{}).proxyHTTPOverGRPC(recorder, request, tunnel); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("response = %d %v", recorder.Code, recorder.Header())
	}
	if body := recorder.Body.String(); body != "event: first\n\nevent: second\n\n" {
		t.Fatalf("streamed response = %q", body)
	}

	cancel()
	select {
	case err := <-clientDone:
		if err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("publisher shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publisher did not shut down")
	}
}
