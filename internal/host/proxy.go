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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/mockoidc"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
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

	// Login node discovery (for non-login nodes)
	loginNodeConn   *grpc.ClientConn
	loginNodeClient internalv1.InternalServiceClient
	loginNodeMu     sync.RWMutex
	isLoginNode     bool

	// Mock OIDC server (dev only)
	mockOIDC *mockoidc.Server

	// Unified storage interface (local for login node, proxy for others)
	storage storage.Storage

	// Proxy storage reference (non-login node only, to update connection on discovery)
	proxyStorage *storage.ProxyStorage

	// Email sender (for magic link auth)
	emailSender *EmailSender
}

// NewProxyServer creates a new dual-listener proxy server
func NewProxyServer(cfg *config.Config) (*ProxyServer, error) {
	// Initialize storage based on whether this is a login node
	var proxyStorage *storage.ProxyStorage
	var storageImpl storage.Storage
	var localStorage *storage.LocalStorage

	if cfg.LoginNode {
		// Login node: initialize SQLite and local storage
		db, err := store.InitDB(cfg.DBPath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize database: %w", err)
		}
		localStorage = storage.NewLocalStorage(db)
		storageImpl = localStorage
		common.LogInfo("login node initialized", "db_path", cfg.DBPath)
	} else {
		// Non-login node: use proxy storage (connection set later during discovery)
		proxyStorage = storage.NewProxyStorage()
		storageImpl = proxyStorage
		common.LogInfo("non-login node, will proxy storage to login node")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"}, // HTTP/2 will negotiate via ALPN
	}

	// Load user tokens from users.yaml if configured
	var userTokens map[string]string
	if cfg.UsersFile != "" {
		userStore, err := store.NewUserStore(cfg.UsersFile)
		if err != nil {
			common.LogError("failed to load users file", "path", cfg.UsersFile, "error", err)
			// Continue without user tokens - not fatal
		} else {
			userTokens = userStore.GetTokenMap()
			common.LogInfo("loaded users file", "path", cfg.UsersFile, "count", userStore.Count())
		}
	}

	// Get account store for subdomain reservations (login node only, direct access)
	var accounts *store.AccountStore
	if localStorage != nil {
		accounts = localStorage.AccountStore()
	}

	// Create gRPC server for public tunnel control plane
	grpcServer := grpc.NewServer()
	tunnelServer := NewTunnelServer(cfg, userTokens, accounts)
	pb.RegisterTunnelServiceServer(grpcServer, tunnelServer)

	// Create gRPC server for internal node-to-node communication
	internalTLSConfig, err := createInternalTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create internal TLS config: %w", err)
	}
	internalGRPCServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(internalTLSConfig)),
		grpc.UnaryInterceptor(nodeSecretInterceptor(cfg.NodeSecret)),
	)
	internalServer := NewInternalServer(tunnelServer, cfg.PublicAddr, cfg.LoginNode)
	internalv1.RegisterInternalServiceServer(internalGRPCServer, internalServer)

	// Register LoginNodeDB service on login node only
	if localStorage != nil {
		loginNodeDBServer := NewLoginNodeDBServer(localStorage)
		internalv1.RegisterLoginNodeDBServer(internalGRPCServer, loginNodeDBServer)
		common.LogInfo("registered LoginNodeDB gRPC service")
	}

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

	// Create email sender if SMTP is configured
	emailSender := NewEmailSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPFrom)
	if emailSender != nil {
		common.LogInfo("email sender configured", "host", cfg.SMTPHost)
	}

	proxy := &ProxyServer{
		Domain:             cfg.Domain,
		CertFile:           cfg.CertFile,
		KeyFile:            cfg.KeyFile,
		HTTP2Addr:          cfg.HTTP2Addr,
		HTTP3Addr:          cfg.HTTP3Addr,
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
		storage:            storageImpl,
		proxyStorage:       proxyStorage,
		emailSender:        emailSender,
		isLoginNode:        cfg.LoginNode,
	}

	// Discover and connect to other nodes in the mesh
	nodeAddresses := discoverNodes(cfg)
	for _, addr := range nodeAddresses {
		// Create a gRPC client connection
		conn, err := createInternalClient(addr, cfg)
		if err != nil {
			common.LogError("failed to create internal client", "addr", addr, "error", err)
			continue // Don't fail startup if one node is unreachable
		}
		proxy.nodeClients[addr] = internalv1.NewInternalServiceClient(conn)
	}

	// If we're not the login node, find and connect to it
	if !cfg.LoginNode {
		proxy.findAndConnectLoginNode()
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
	tlsConfig := &tls.Config{}

	// If custom CA cert is specified (self-hosters), load it
	if cfg.InternalCACert != "" {
		caCert, err := os.ReadFile(cfg.InternalCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert %s: %w", cfg.InternalCACert, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", cfg.InternalCACert)
		}

		tlsConfig.RootCAs = caCertPool
		common.LogInfo("using custom CA for internal TLS", "ca_cert", cfg.InternalCACert)
	}
	// Otherwise use system CA pool (tunn.to uses Let's Encrypt, which is trusted)

	return grpc.Dial(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(&nodeSecretCreds{secret: cfg.NodeSecret}),
	)
}

// discoverNodes discovers other nodes in the mesh using Fly.io internal DNS
// Falls back to NODE_ADDRESSES if DNS discovery fails or is not configured
func discoverNodes(cfg *config.Config) []string {
	var nodeAddresses []string

	// Try Fly.io DNS discovery first
	if cfg.FlyAppName != "" {
		dnsName := cfg.FlyAppName + ".internal"
		ips, err := net.LookupIP(dnsName)
		if err != nil {
			common.LogError("DNS discovery failed, falling back to NODE_ADDRESSES",
				"dns_name", dnsName, "error", err)
		} else {
			// Get current node's IPs to filter out self
			selfIPs := getSelfIPs()

			// Get gRPC port from config (default 50051)
			port := strings.TrimPrefix(cfg.InternalGRPCPort, ":")
			if port == "" {
				port = "50051"
			}

			for _, ip := range ips {
				// Skip self
				if selfIPs[ip.String()] {
					continue
				}
				// Only use IPv6 addresses for Fly.io internal networking
				if ip.To4() == nil {
					nodeAddresses = append(nodeAddresses, fmt.Sprintf("[%s]:%s", ip.String(), port))
				}
			}

			if len(nodeAddresses) > 0 {
				common.LogInfo("discovered nodes via DNS",
					"dns_name", dnsName,
					"count", len(nodeAddresses),
					"addresses", nodeAddresses)
				return nodeAddresses
			}
			common.LogInfo("DNS discovery found no other nodes", "dns_name", dnsName)
		}
	}

	// Fall back to NODE_ADDRESSES
	if cfg.NodeAddresses != "" {
		for _, addr := range strings.Split(cfg.NodeAddresses, ",") {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				nodeAddresses = append(nodeAddresses, addr)
			}
		}
		if len(nodeAddresses) > 0 {
			common.LogInfo("using NODE_ADDRESSES for node discovery",
				"count", len(nodeAddresses),
				"addresses", nodeAddresses)
		}
	}

	return nodeAddresses
}

// getSelfIPs returns a set of this machine's IP addresses
func getSelfIPs() map[string]bool {
	selfIPs := make(map[string]bool)

	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return selfIPs
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				selfIPs[ipnet.IP.String()] = true
			}
		}
	}

	return selfIPs
}

// nodeSecretCreds implements credentials.PerRPCCredentials for node-to-node auth
type nodeSecretCreds struct {
	secret string
}

func (c *nodeSecretCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"x-node-secret": c.secret,
	}, nil
}

func (c *nodeSecretCreds) RequireTransportSecurity() bool {
	return true // Always require TLS
}

// ipBlacklist tracks IPs that have failed node secret auth
var ipBlacklist = struct {
	sync.RWMutex
	entries map[string]time.Time
}{entries: make(map[string]time.Time)}

const blacklistDuration = 10 * time.Second

// nodeSecretInterceptor creates a gRPC interceptor that verifies the x-node-secret header
func nodeSecretInterceptor(secret string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Get peer IP from context
		peerIP := getPeerIP(ctx)

		// Check if IP is blacklisted
		ipBlacklist.RLock()
		if expiry, ok := ipBlacklist.entries[peerIP]; ok && time.Now().Before(expiry) {
			ipBlacklist.RUnlock()
			return nil, status.Error(codes.PermissionDenied, "temporarily blocked")
		}
		ipBlacklist.RUnlock()

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			blacklistIP(peerIP)
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		secrets := md.Get("x-node-secret")
		if len(secrets) == 0 || secrets[0] != secret {
			blacklistIP(peerIP)
			common.LogError("invalid node secret attempt", "ip", peerIP)
			return nil, status.Error(codes.Unauthenticated, "invalid node secret")
		}

		return handler(ctx, req)
	}
}

// blacklistIP adds an IP to the blacklist for blacklistDuration
func blacklistIP(ip string) {
	if ip == "" {
		return
	}
	ipBlacklist.Lock()
	ipBlacklist.entries[ip] = time.Now().Add(blacklistDuration)
	ipBlacklist.Unlock()
}

// getPeerIP extracts the peer IP from gRPC context
func getPeerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	// Extract IP from addr (format: "ip:port" or "[ipv6]:port")
	addr := p.Addr.String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
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

	// Start login node discovery loop (for non-login nodes)
	if !p.isLoginNode {
		go p.loginNodeDiscoveryLoop(ctx)
	}

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

		// Shutdown mock OIDC server if running
		if p.mockOIDC != nil {
			common.LogInfo("shutting down mock OIDC server")
			p.mockOIDC.Shutdown()
		}

		// Shutdown internal gRPC server
		common.LogInfo("shutting down internal gRPC server")
		p.internalGRPCServer.Stop() // Use Stop() instead of GracefulStop() to avoid hanging

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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
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
			common.LogDebug("routing to gRPC", "path", r.URL.Path, "content-type", contentType)
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

	// Install script endpoint
	mux.HandleFunc("/install.sh", p.handleInstallScript)

	// Auth endpoints (no auth required on these)
	mux.HandleFunc("/auth/login", p.handleLogin)
	mux.HandleFunc("/auth/github", p.handleGitHubLogin)
	mux.HandleFunc("/auth/callback", p.handleCallback)
	mux.HandleFunc("/auth/magic", p.handleMagicLinkRequest)
	mux.HandleFunc("/auth/verify", p.handleMagicLinkVerify)

	// Device code flow for CLI login
	mux.HandleFunc("/api/device/code", p.handleDeviceCode)
	mux.HandleFunc("/api/device/token", p.handleDeviceToken)
	mux.HandleFunc("/login", p.handleLoginPage)

	// UDP proxy endpoint (for tunn connect)
	mux.HandleFunc("/udp/", p.handleUDPProxy)

	// Stripe webhook endpoint
	mux.HandleFunc("/webhooks/stripe", p.handleStripeWebhook)

	// Main handler - check if this is apex domain or a tunnel subdomain
	mux.HandleFunc("/", p.handleWebProxy)

	// Wrap the mux with session manager middleware
	return p.sessionManager.LoadAndSave(mux)
}

// handleInstallScript serves the install script for curl | sh installation
func (p *ProxyServer) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, installScript)
}

// installScript is the embedded install.sh content
const installScript = `#!/bin/sh
# tunn installer
# Usage: curl -fsSL https://tunn.to/install.sh | sh

set -e

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    darwin|linux) ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Get latest release version
LATEST=$(curl -fsSL https://api.github.com/repos/ehrlich-b/tunn/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$LATEST" ]; then
    echo "Failed to get latest release version"
    exit 1
fi

BINARY="tunn-${OS}-${ARCH}"
URL="https://github.com/ehrlich-b/tunn/releases/download/${LATEST}/${BINARY}"

# Determine install location
if [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
elif [ -d "$HOME/.local/bin" ]; then
    INSTALL_DIR="$HOME/.local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

echo "Downloading tunn ${LATEST} for ${OS}/${ARCH}..."
curl -fsSL "$URL" -o "$INSTALL_DIR/tunn"
chmod +x "$INSTALL_DIR/tunn"

echo ""
echo "tunn installed to $INSTALL_DIR/tunn"

# Check if install dir is in PATH
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "Add $INSTALL_DIR to your PATH to use tunn" ;;
esac

echo ""
echo "Run 'tunn --help' to get started"
`

func createInternalTLSConfig(cfg *config.Config) (*tls.Config, error) {
	// Reuse the public cert for internal gRPC server
	serverCert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		// No client auth - we use x-node-secret header for authentication
	}, nil
}

// findAndConnectLoginNode discovers which peer is the login node and connects to it
func (p *ProxyServer) findAndConnectLoginNode() bool {
	p.loginNodeMu.Lock()
	defer p.loginNodeMu.Unlock()

	// Query each peer to find the login node (with delay between queries)
	for addr, client := range p.nodeClients {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := client.GetNodeInfo(ctx, &internalv1.NodeInfoRequest{})
		cancel()

		if err != nil {
			common.LogError("failed to get node info", "addr", addr, "error", err)
			time.Sleep(500 * time.Millisecond) // Delay before next query
			continue
		}

		if resp.IsLoginNode {
			// Found the login node
			common.LogInfo("discovered login node", "addr", addr, "node_id", resp.NodeId)

			// Create a dedicated connection to the login node
			conn, err := createInternalClient(addr, p.config)
			if err != nil {
				common.LogError("failed to connect to login node", "addr", addr, "error", err)
				time.Sleep(500 * time.Millisecond)
				continue
			}

			// Close existing connection if any
			if p.loginNodeConn != nil {
				p.loginNodeConn.Close()
			}

			p.loginNodeConn = conn
			p.loginNodeClient = internalv1.NewInternalServiceClient(conn)

			// Update proxy storage connection (for non-login nodes)
			if p.proxyStorage != nil {
				p.proxyStorage.SetConnection(conn)
				common.LogInfo("proxy storage connected to login node")
			}

			return true
		}

		time.Sleep(500 * time.Millisecond) // Delay before next query
	}

	common.LogInfo("no login node found among peers (may be single-node or all nodes are proxies)")
	return false
}

// LoginNodeAvailable returns true if the login node is connected and healthy
func (p *ProxyServer) LoginNodeAvailable() bool {
	// If we are the login node, it's always available
	if p.isLoginNode {
		return true
	}

	p.loginNodeMu.RLock()
	defer p.loginNodeMu.RUnlock()

	if p.loginNodeConn == nil {
		return false
	}

	// Check connection state
	state := p.loginNodeConn.GetState()
	return state == connectivity.Idle || state == connectivity.Connecting || state == connectivity.Ready
}

// IsLoginNode returns true if this proxy is the login node
func (p *ProxyServer) IsLoginNode() bool {
	return p.isLoginNode
}

// GetLoginNodeClient returns the gRPC client for the login node
// Returns nil if this is the login node or no login node is connected
func (p *ProxyServer) GetLoginNodeClient() internalv1.InternalServiceClient {
	p.loginNodeMu.RLock()
	defer p.loginNodeMu.RUnlock()
	return p.loginNodeClient
}

// loginNodeDiscoveryLoop continuously tries to find and stay connected to the login node
func (p *ProxyServer) loginNodeDiscoveryLoop(ctx context.Context) {
	const (
		minBackoff = 1 * time.Second
		maxBackoff = 15 * time.Second
	)

	backoff := minBackoff

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if p.LoginNodeAvailable() {
			// Connected - check again in 30 seconds
			backoff = minBackoff // Reset backoff on success
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}

		// Not connected - try to find login node
		common.LogInfo("login node not available, attempting discovery", "backoff", backoff)
		if p.findAndConnectLoginNode() {
			backoff = minBackoff // Reset on success
		} else {
			// Exponential backoff on failure
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}
