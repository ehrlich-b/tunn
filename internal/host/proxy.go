package host

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/mockoidc"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
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

	// gRPC server for internal node-to-node communication
	internalGRPCServer *grpc.Server
	internalServer     *InternalServer
	nodeClients        map[string]internalv1.InternalServiceClient
	tunnelCache        map[string]string // tunnelID -> nodeAddress
	cacheMu            sync.RWMutex

	// Session manager for web auth
	sessionManager *scs.SessionManager

	// Configuration
	config *config.Config

	PublicAddr string

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

	// Create gRPC server for public tunnel control plane
	grpcServer := grpc.NewServer()
	tunnelServer := NewTunnelServer(cfg.WellKnownKey)
	pb.RegisterTunnelServiceServer(grpcServer, tunnelServer)

	// Create gRPC server for internal node-to-node communication
	internalTLSConfig, err := createInternalTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create internal TLS config: %w", err)
	}
	internalGRPCServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(internalTLSConfig)))
	internalServer := NewInternalServer(tunnelServer, cfg.PublicAddr)
	internalv1.RegisterInternalServiceServer(internalGRPCServer, internalServer)

	// Create session manager for web auth
	sessionManager := scs.New()
	sessionManager.Lifetime = 24 * time.Hour
	sessionManager.Cookie.Name = "tunn_session"
	sessionManager.Cookie.Persist = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	sessionManager.Cookie.Secure = true

	// Set cookie domain to allow sharing across subdomains
	// e.g., .tunn.to allows cookie to be sent to *.tunn.to
	sessionManager.Cookie.Domain = "." + cfg.Domain

	proxy := &ProxyServer{
		Domain:             cfg.Domain,
		CertFile:           cfg.CertFile,
		KeyFile:            cfg.KeyFile,
		HTTP2Addr:          ":8443", // Internal HTTP/2 port (Fly.io routes 443/tcp here)
		HTTP3Addr:          ":8443", // Internal HTTP/3 port (Fly.io routes 443/udp here)
		tlsConfig:          tlsConfig,
		grpcServer:         grpcServer,
		tunnelServer:       tunnelServer,
		internalGRPCServer: internalGRPCServer,
		internalServer:     internalServer,
		sessionManager:     sessionManager,
		nodeClients:        make(map[string]internalv1.InternalServiceClient),
		tunnelCache:        make(map[string]string),
		config:             cfg,
		PublicAddr:         cfg.PublicAddr,
	}

	// Create gRPC clients for other nodes
	nodeAddresses := strings.Split(cfg.NodeAddresses, ",")
	for _, addr := range nodeAddresses {
		if addr != "" {
			// Create a gRPC client connection
			conn, err := createInternalClient(addr, cfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create internal client for %s: %w", addr, err)
			}
			proxy.nodeClients[addr] = internalv1.NewInternalServiceClient(conn)
		}
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

// ... (rest of the file)

func createInternalClient(addr string, cfg *config.Config) (*grpc.ClientConn, error) {
	// Load certificate of the CA who signed server's certificate
	caCert, err := os.ReadFile(cfg.InternalCACertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read internal CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load client's certificate and private key
	clientCert, err := tls.LoadX509KeyPair(cfg.InternalNodeCertFile, cfg.InternalNodeKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load internal node cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
	}

	return grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
}

// Run starts both HTTP/2 and HTTP/3 listeners
func (p *ProxyServer) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 4)

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

	// Start internal gRPC server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.startInternalServer(ctx); err != nil {
			errChan <- fmt.Errorf("internal gRPC server error: %w", err)
		}
	}()

	common.LogInfo("proxy server ready",
		"http2", p.HTTP2Addr,
		"http3", p.HTTP3Addr,
		"internal_grpc", p.config.InternalGRPCPort,
		"domain", p.Domain,
		"env", p.config.Environment)

	// Wait for either an error or context cancellation
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		common.LogInfo("shutting down proxy server")
		p.internalGRPCServer.GracefulStop()
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

// startInternalServer starts the gRPC server for internal node-to-node communication
func (p *ProxyServer) startInternalServer(ctx context.Context) error {
	lis, err := net.Listen("tcp", p.config.InternalGRPCPort)
	if err != nil {
		return fmt.Errorf("failed to listen on internal port: %w", err)
	}

	common.LogInfo("starting internal gRPC server", "addr", p.config.InternalGRPCPort)

	go func() {
		<-ctx.Done()
		common.LogInfo("shutting down internal gRPC server")
		p.internalGRPCServer.GracefulStop()
	}()

	if err := p.internalGRPCServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
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

	// Health check endpoint (no auth required)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// Auth endpoints (no auth required on these)
	mux.HandleFunc("/auth/login", p.handleLogin)
	mux.HandleFunc("/auth/callback", p.handleCallback)

	// Main handler - check if this is apex domain or a tunnel subdomain
	mux.HandleFunc("/", p.handleWebProxy)

	// Wrap the mux with session manager middleware
	return p.sessionManager.LoadAndSave(mux)
}

func createInternalTLSConfig(cfg *config.Config) (*tls.Config, error) {
	// Load certificate of the CA who signed server's certificate
	caCert, err := os.ReadFile(cfg.InternalCACertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read internal CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(cfg.InternalNodeCertFile, cfg.InternalNodeKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load internal node cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		RootCAs:      caCertPool,
	}, nil
}
