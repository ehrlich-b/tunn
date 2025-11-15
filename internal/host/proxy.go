package host

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/mockoidc"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// ProxyServer is the new V1 dual-listener proxy server
type ProxyServer struct {
	Domain   string
	CertFile string
	KeyFile  string

	// HTTP/2 (TCP) listener address
	HTTP2Addr string
	// HTTP/3 (QUIC) listener address
	HTTP3Addr string

	// TLS configuration
	tlsConfig *tls.Config

	// gRPC server for tunnel control plane
	grpcServer   *grpc.Server
	tunnelServer *TunnelServer

	// Configuration
	config *config.Config

	// Mock OIDC server (dev only)
	mockOIDC *mockoidc.Server
}

// NewProxyServer creates a new dual-listener proxy server
func NewProxyServer(cfg *config.Config) (*ProxyServer, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"}, // HTTP/2 will negotiate via ALPN
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()
	tunnelServer := NewTunnelServer()
	pb.RegisterTunnelServiceServer(grpcServer, tunnelServer)

	proxy := &ProxyServer{
		Domain:       cfg.Domain,
		CertFile:     cfg.CertFile,
		KeyFile:      cfg.KeyFile,
		HTTP2Addr:    ":8443", // Internal HTTP/2 port (Fly.io routes 443/tcp here)
		HTTP3Addr:    ":8443", // Internal HTTP/3 port (Fly.io routes 443/udp here)
		tlsConfig:    tlsConfig,
		grpcServer:   grpcServer,
		tunnelServer: tunnelServer,
		config:       cfg,
	}

	// Set up mock OIDC server in dev mode
	if cfg.IsDev() && cfg.MockOIDCAddr != "" {
		mockOIDC, err := mockoidc.New(mockoidc.Config{
			Addr:   cfg.MockOIDCAddr,
			Issuer: cfg.MockOIDCIssuer,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create mock OIDC server: %w", err)
		}
		proxy.mockOIDC = mockOIDC
		common.LogInfo("mock OIDC server configured", "addr", cfg.MockOIDCAddr, "issuer", cfg.MockOIDCIssuer)
	}

	return proxy, nil
}

// Run starts both HTTP/2 and HTTP/3 listeners
func (p *ProxyServer) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 3)

	// Start mock OIDC server in dev mode
	if p.mockOIDC != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			common.LogInfo("starting mock OIDC server", "addr", p.config.MockOIDCAddr)
			if err := p.mockOIDC.Start(); err != nil {
				errChan <- fmt.Errorf("mock OIDC server error: %w", err)
			}
		}()
	}

	// Create the HTTP handler (will be used by both servers)
	handler := p.createHandler()

	// Start HTTP/2 (TCP) server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.startHTTP2Server(ctx, handler); err != nil {
			errChan <- fmt.Errorf("HTTP/2 server error: %w", err)
		}
	}()

	// Start HTTP/3 (QUIC) server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.startHTTP3Server(ctx, handler); err != nil {
			errChan <- fmt.Errorf("HTTP/3 server error: %w", err)
		}
	}()

	common.LogInfo("proxy server ready",
		"http2", p.HTTP2Addr,
		"http3", p.HTTP3Addr,
		"domain", p.Domain,
		"env", p.config.Environment)

	// Wait for either an error or context cancellation
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		common.LogInfo("shutting down proxy server")
		wg.Wait()
		return ctx.Err()
	}
}

// startHTTP2Server starts the HTTP/2 (TCP) listener with gRPC/HTTPS routing
func (p *ProxyServer) startHTTP2Server(ctx context.Context, handler http.Handler) error {
	// Create a router that handles both gRPC and HTTPS
	router := p.createHTTP2Router(handler)

	srv := &http.Server{
		Addr:      p.HTTP2Addr,
		Handler:   router,
		TLSConfig: p.tlsConfig,
	}

	// Enable HTTP/2
	http2.ConfigureServer(srv, &http2.Server{})

	common.LogInfo("starting HTTP/2 server", "addr", p.HTTP2Addr)

	// Start server in a goroutine
	go func() {
		<-ctx.Done()
		common.LogInfo("shutting down HTTP/2 server")
		srv.Shutdown(context.Background())
	}()

	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

// startHTTP3Server starts the HTTP/3 (QUIC) listener
func (p *ProxyServer) startHTTP3Server(ctx context.Context, handler http.Handler) error {
	srv := &http3.Server{
		Addr:      p.HTTP3Addr,
		Handler:   handler,
		TLSConfig: p.tlsConfig,
	}

	common.LogInfo("starting HTTP/3 server", "addr", p.HTTP3Addr)

	// Start server in a goroutine
	go func() {
		<-ctx.Done()
		common.LogInfo("shutting down HTTP/3 server")
		srv.Close()
	}()

	if err := srv.ListenAndServeTLS(p.CertFile, p.KeyFile); err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

// createHTTP2Router creates a router that handles both gRPC and HTTPS traffic
func (p *ProxyServer) createHTTP2Router(httpHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is a gRPC request by examining the Content-Type header
		contentType := r.Header.Get("Content-Type")
		if strings.HasPrefix(contentType, "application/grpc") {
			// Route to gRPC server
			common.LogInfo("routing to gRPC", "path", r.URL.Path, "content-type", contentType)
			p.grpcServer.ServeHTTP(w, r)
			return
		}

		// Otherwise, route to HTTP handler
		httpHandler.ServeHTTP(w, r)
	})
}

// createHandler creates the HTTP handler for both servers
func (p *ProxyServer) createHandler() http.Handler {
	mux := http.NewServeMux()

	// Placeholder for now - will be implemented in next steps
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "tunn v1 proxy server\nprotocol: %s\n", r.Proto)
	})

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	return mux
}
