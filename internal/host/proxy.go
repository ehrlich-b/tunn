package host

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/downloads"
	"github.com/ehrlich-b/tunn/internal/identity"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/mockoidc"
	"github.com/ehrlich-b/tunn/internal/sshfront"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// ProxyServer is the new V1 dual-listener proxy server
type ProxyServer struct {
	listenerState     atomic.Uint32
	requiredListeners atomic.Uint32
	stopping          atomic.Bool
	sshServer         *sshfront.Server
	sshKeys           *sshfront.Registry
	Domain            string
	CertFile          string
	KeyFile           string

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

	// Configuration
	config *config.Config

	PublicAddr string

	// Login node discovery (for non-login nodes)
	loginNodeConn     *grpc.ClientConn
	loginNodeClient   internalv1.InternalServiceClient
	loginNodeMu       sync.RWMutex
	loginNodeHTTPAddr string
	isLoginNode       bool

	// Mock OIDC server (dev only)
	mockOIDC *mockoidc.Server

	// Unified storage interface (local for login node, proxy for others)
	storage           storage.Storage
	meter             metering.Backend
	planMeter         bool
	domains           domains.Backend
	domainRegistry    *domains.Registry
	operations        operationalCounters
	googleHTTPClient  *http.Client // Optional provider transport for tests.
	orgOIDCHTTPClient *http.Client
	orgLogins         *orgLoginStore
	orgProvidersMu    sync.Mutex
	orgProviders      map[string]*orgProvider
	orgProviderInits  map[string]*orgProviderInit
	mcpOAuth          *mcpOAuthStore
	devices           *deviceCredentialStore
	appDevices        *appDeviceStore

	// Proxy storage reference (non-login node only, to update connection on discovery)
	proxyStorage *storage.ProxyStorage

	// Email sender (for magic link auth)
	emailSender interface {
		SendMagicLink(string, string) error
		Send(string, string, string) error
	}
	now        func() time.Time
	sessionNow func() time.Time

	// Graceful degradation (non-login nodes)
	usageBuffer *UsageBuffer
	quotaCache  *QuotaCache

	// Device code rate limiting (per-IP)
	deviceCodeRateMu   sync.Mutex
	deviceCodeRateByIP map[string][]time.Time
}

// NewProxyServer creates a new dual-listener proxy server
func NewProxyServer(cfg *config.Config) (*ProxyServer, error) {
	if err := cfg.ValidateOIDCOrgs(); err != nil {
		return nil, err
	}
	if cfg.HostModeEnabled && (!cfg.LoginNode || cfg.PublicMode || cfg.NodeAddresses != "" || cfg.FlyAppName != "") {
		return nil, fmt.Errorf("host mode requires one authenticated, standalone login relay")
	}
	// SECURITY: Require NodeSecret when multi-node mode is enabled
	// Multi-node can be configured via NODE_ADDRESSES (static) or FLY_APP_NAME (DNS discovery)
	isMultiNode := cfg.NodeAddresses != "" || cfg.FlyAppName != ""
	if isMultiNode && cfg.NodeSecret == "" {
		return nil, fmt.Errorf("TUNN_NODE_SECRET must be set for multi-node mode (detected via TUNN_NODE_ADDRESSES or FLY_APP_NAME)")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TUNN_CERT_FILE/TUNN_KEY_FILE: %w", err)
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
			return nil, fmt.Errorf("failed to load TUNN_USERS_FILE: %w", err)
		} else {
			userTokens = userStore.GetTokenMap()
			common.LogInfo("loaded users file", "path", cfg.UsersFile, "count", userStore.Count())
		}
	}

	internalTLSConfig, err := createInternalTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create internal TLS config: %w", err)
	}
	if cfg.InternalCACert != "" {
		if _, err := loadInternalCA(cfg.InternalCACert); err != nil {
			return nil, err
		}
	}

	// Initialize storage based on whether this is a login node
	var proxyStorage *storage.ProxyStorage
	var storageImpl storage.Storage
	var localStorage *storage.LocalStorage
	var localMeter *metering.Store
	var localOAuth *mcpOAuthStore
	var localDevices *deviceCredentialStore
	var localAppDevices *appDeviceStore
	var localOrgLogins *orgLoginStore

	if cfg.LoginNode {
		// Login node: initialize SQLite and local storage
		db, err := store.InitDB(cfg.DBPath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize database: %w", err)
		}
		localDevices, err = newDeviceCredentialStore(db)
		if err != nil {
			return nil, fmt.Errorf("initialize device credentials: %w", err)
		}
		localStorage = storage.NewLocalStorage(db)
		localStorage.ConfigureStripeAutomation(cfg.StripeSecretKey, cfg.StripeProPriceIDs)
		localAppDevices, err = newAppDeviceStore(db)
		if err != nil {
			return nil, fmt.Errorf("initialize app devices: %w", err)
		}
		if len(cfg.OIDCOrgs) > 0 {
			localOrgLogins, err = newOrgLoginStore(db)
			if err != nil {
				return nil, fmt.Errorf("initialize organization logins: %w", err)
			}
		}
		localMeter, err = metering.New(db, metering.WithAccountPlans(), metering.WithOwnerBudgets(cfg.OwnerMonthlyRequests, cfg.OwnerMonthlyBytes))
		if err != nil {
			return nil, fmt.Errorf("initialize ingress meter: %w", err)
		}
		storageImpl = localStorage
		localOAuth, err = newMCPOAuthStore(db)
		if err != nil {
			return nil, fmt.Errorf("initialize MCP authorization: %w", err)
		}
		common.LogInfo("login node initialized", "db_path", cfg.DBPath)
	} else {
		// Non-login node: use proxy storage (connection set later during discovery)
		proxyStorage = storage.NewProxyStorage()
		storageImpl = proxyStorage
		common.LogInfo("non-login node, will proxy storage to login node")
	}

	// Get account store for subdomain reservations (login node only, direct access)
	var accounts *store.AccountStore
	if localStorage != nil {
		accounts = localStorage.AccountStore()
	}

	// Create gRPC server for public tunnel control plane with keepalive
	grpcServer := grpc.NewServer(
		grpc.WaitForHandlers(true),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    10 * time.Second, // Ping clients every 10s
			Timeout: 5 * time.Second,  // Wait 5s for pong
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second, // Allow client pings every 5s
			PermitWithoutStream: true,            // Allow pings even with no active streams
		}),
	)
	tunnelServer := NewTunnelServer(cfg, userTokens, accounts, storageImpl)
	if cfg.HostModeEnabled {
		if err := tunnelServer.EnableHostMode(store.DB()); err != nil {
			return nil, err
		}
	}
	pb.RegisterTunnelServiceServer(grpcServer, tunnelServer)

	// Create gRPC server for internal node-to-node communication
	internalGRPCServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(internalTLSConfig)),
		grpc.UnaryInterceptor(nodeSecretInterceptor(cfg.NodeSecret)),
	)
	internalServer := NewInternalServer(tunnelServer, cfg.PublicAddr, cfg.LoginNode)
	internalv1.RegisterInternalServiceServer(internalGRPCServer, internalServer)

	// Register LoginNodeDB service on login node only
	if localStorage != nil {
		loginNodeDBServer := NewLoginNodeDBServer(localStorage)
		loginNodeDBServer.appDevices = localAppDevices
		internalv1.RegisterLoginNodeDBServer(internalGRPCServer, loginNodeDBServer)
		meterpb.RegisterMeteringServer(internalGRPCServer, localMeter)
		common.LogInfo("registered LoginNodeDB gRPC service")
	}

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
		nodeClients:        make(map[string]internalv1.InternalServiceClient),
		tunnelCache:        make(map[string]string),
		config:             cfg,
		PublicAddr:         cfg.PublicAddr,
		storage:            storageImpl,
		planMeter:          true,
		mcpOAuth:           localOAuth,
		devices:            localDevices,
		appDevices:         localAppDevices,
		orgLogins:          localOrgLogins,
		proxyStorage:       proxyStorage,
		isLoginNode:        cfg.LoginNode,
		usageBuffer:        NewUsageBuffer(),
		quotaCache:         NewQuotaCache(30 * time.Second),
		deviceCodeRateByIP: make(map[string][]time.Time),
	}
	if localOAuth != nil {
		localOAuth.now = proxy.currentTime
	}
	if emailSender != nil {
		proxy.emailSender = emailSender
	}

	if localMeter != nil {
		proxy.meter = localMeter
	} else {
		proxy.meter = &metering.Remote{Connection: func() *grpc.ClientConn {
			proxy.loginNodeMu.RLock()
			defer proxy.loginNodeMu.RUnlock()
			return proxy.loginNodeConn
		}}
	}

	tunnelServer.sharing, _ = proxy.meter.(metering.SharingBackend)
	if cfg.CustomDomainsEnabled {
		if _, err := identity.Load(cfg.IdentityKeysFile); err != nil {
			return nil, fmt.Errorf("TUNN_IDENTITY_KEYS_FILE: %w", err)
		}
		if cfg.LoginNode {
			key, err := base64.StdEncoding.DecodeString(cfg.DomainKeySecret)
			if err != nil || len(key) != 32 {
				return nil, fmt.Errorf("TUNN_DOMAIN_KEY_SECRET must be a base64-encoded 32-byte key")
			}
			registry, err := domains.New(store.DB(), cfg.Domain, key, nil, nil)
			if err != nil {
				return nil, err
			}
			if err := registry.ConfigureACME(cfg.ACMEDirectory, cfg.ACMEEmail, nil); err != nil {
				return nil, err
			}
			proxy.domains, proxy.domainRegistry = registry, registry
			domainpb.RegisterDomainsServer(internalGRPCServer, registry)
		} else {
			proxy.domains = &domains.Remote{Connection: func() *grpc.ClientConn {
				proxy.loginNodeMu.RLock()
				defer proxy.loginNodeMu.RUnlock()
				return proxy.loginNodeConn
			}}
		}
		proxy.tlsConfig.GetCertificate = proxy.domainCertificate(cert)
	}
	if cfg.SSHHostKeyFile != "" {
		if !cfg.LoginNode {
			return nil, fmt.Errorf("SSH requires the login node for durable key ownership; route raw SSH traffic there")
		}
		if err := proxy.enableSSH(store.DB()); err != nil {
			return nil, err
		}
	}

	internalServer.proxy = proxy

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

func createInternalClient(addr string, cfg *config.Config) (*grpc.ClientConn, error) {
	tlsConfig := &tls.Config{
		// Set ServerName for proper TLS verification when dialing by IP address.
		// The cert is issued for the domain (e.g., tunn.to), not IP addresses.
		ServerName: cfg.Domain,
	}

	// If custom CA cert is specified (self-hosters), load it
	if cfg.InternalCACert != "" {
		caCertPool, err := loadInternalCA(cfg.InternalCACert)
		if err != nil {
			return nil, err
		}

		tlsConfig.RootCAs = caCertPool
		common.LogInfo("using custom CA for internal TLS", "ca_cert", cfg.InternalCACert)
	}
	// Otherwise use system CA pool (tunn.to uses Let's Encrypt, which is trusted)

	return grpc.NewClient("passthrough:///"+addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(&nodeSecretCreds{secret: cfg.NodeSecret}),
	)
}

func loadInternalCA(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read TUNN_CA_CERT: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("TUNN_CA_CERT must contain a PEM certificate")
	}
	return pool, nil
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
		if secret == "" {
			return nil, status.Error(codes.FailedPrecondition, "internal node authentication is not configured")
		}
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
		if len(secrets) == 0 || subtle.ConstantTimeCompare([]byte(secrets[0]), []byte(secret)) != 1 {
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

// init starts the IP blacklist cleanup goroutine
func init() {
	go cleanupBlacklist()
}

// cleanupBlacklist periodically removes expired entries from the IP blacklist
func cleanupBlacklist() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		ipBlacklist.Lock()
		for ip, expiry := range ipBlacklist.entries {
			if now.After(expiry) {
				delete(ipBlacklist.entries, ip)
			}
		}
		ipBlacklist.Unlock()
	}
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

// Run starts HTTP/2 and the configured optional HTTP/3 listener
func (p *ProxyServer) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	errChan := make(chan error, 6)
	p.stopping.Store(false)
	http3Enabled := p.config.HTTP3Enabled()
	common.LogInfo("HTTP/3 configuration", "enabled", http3Enabled)
	required := uint32(listenerHTTP2 | listenerInternal)
	if http3Enabled {
		required |= listenerHTTP3
	}
	if p.sshServer != nil && p.config.SSHAddr != "" {
		required |= listenerSSH
	}
	if p.domains != nil {
		required |= listenerHTTP01
	}
	p.requiredListeners.Store(required)
	defer func() {
		p.stopping.Store(true)
		cancel()
		// Long-lived publisher streams must close before HTTP shutdown waits.
		p.grpcServer.Stop()
		p.internalGRPCServer.Stop()
		wg.Wait()
		p.listenerState.Store(0)
	}()

	// Start mock OIDC server in dev mode
	if p.mockOIDC != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			common.LogInfo("starting mock OIDC server", "addr", p.config.MockOIDCAddr)
			if err := p.mockOIDC.StartContext(ctx); err != nil {
				errChan <- fmt.Errorf("mock OIDC server error: %w", err)
			}
		}()
	}

	// Create the HTTP handler (will be used by both servers)
	handler := p.createHandler()
	if p.sshServer != nil && p.config.SSHAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := net.Listen("tcp", p.config.SSHAddr)
			if err == nil {
				p.listenerStarted(listenerSSH)
				defer p.listenerState.And(^uint32(listenerSSH))
				err = p.sshServer.Serve(ctx, l)
			}
			if err != nil {
				errChan <- fmt.Errorf("SSH listener error: %w", err)
			}
		}()
	}

	if p.domains != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.startHTTP01Server(ctx); err != nil {
				errChan <- fmt.Errorf("HTTP-01 server error: %w", err)
			}
		}()
		if p.domainRegistry != nil {
			wg.Add(1)
			go func() { defer wg.Done(); p.domainRegistry.Run(ctx) }()
		}
	}

	// Start HTTP/2 (TCP) server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.startHTTP2Server(ctx, handler); err != nil {
			errChan <- fmt.Errorf("HTTP/2 server error: %w", err)
		}
	}()

	// Start HTTP/3 (QUIC) only when enabled.
	if http3Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.startHTTP3Server(ctx, handler); err != nil {
				errChan <- fmt.Errorf("HTTP/3 server error: %w", err)
			}
		}()
	}

	// Start internal gRPC server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.startInternalServer(ctx); err != nil {
			errChan <- fmt.Errorf("internal gRPC server error: %w", err)
		}
	}()

	if ledger, ok := p.meter.(*metering.Store); ok && p.isLoginNode {
		wg.Add(1)
		go func() { defer wg.Done(); ledger.RunAuditRetention(ctx) }()
	}

	// Start login node discovery loop and usage flush loop (for non-login nodes)
	if !p.isLoginNode {
		wg.Add(2)
		go func() { defer wg.Done(); p.loginNodeDiscoveryLoop(ctx) }()
		go func() { defer wg.Done(); p.usageFlushLoop(ctx) }()
	}

	// Wait for either an error or context cancellation
	if p.isLoginNode {
		wg.Add(1)
		go func() { defer wg.Done(); p.tunnelAlertLoop(ctx) }()
	}
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		common.LogInfo("shutting down proxy server")

		return ctx.Err()
	}
}

// startHTTP2Server starts the HTTP/2 (TCP) listener with gRPC/HTTPS routing
func (p *ProxyServer) startHTTP2Server(ctx context.Context, handler http.Handler) error {
	// Create a router that handles both gRPC and HTTPS
	router := p.createHTTP2Router(handler)
	// Protocol setup mutates TLS settings. Keep the shared template immutable
	// so concurrent HTTP/3 startup can safely clone it.
	tlsConfig := p.tlsConfig.Clone()

	srv := &http.Server{
		Addr:        p.HTTP2Addr,
		Handler:     router,
		TLSConfig:   tlsConfig,
		ConnContext: publisherConnContext,
		// Timeouts - ReadTimeout/WriteTimeout disabled for gRPC streaming support
		// gRPC streams are long-lived and use application-level health checks
		ReadHeaderTimeout: 10 * time.Second,  // Max time to read headers specifically
		IdleTimeout:       120 * time.Second, // Max time connection can be idle between requests
	}

	// Enable HTTP/2
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		return fmt.Errorf("configure HTTP/2 server: %w", err)
	}

	common.LogInfo("starting HTTP/2 server", "addr", p.HTTP2Addr)

	// Create listener explicitly with tcp4 to ensure IPv4 binding
	ln, err := net.Listen("tcp4", p.HTTP2Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.HTTP2Addr, err)
	}
	if p.sshServer != nil {
		ln = sshfront.Share(ctx, ln, p.sshServer.ServeConn)
	}
	tlsLn := tls.NewListener(publisherListener{ln}, tlsConfig)
	p.listenerStarted(listenerHTTP2)
	defer p.listenerState.And(^uint32(listenerHTTP2))

	// Start server in a goroutine
	shutdownDone := make(chan struct{})
	stopShutdown := context.AfterFunc(ctx, func() {
		defer close(shutdownDone)
		common.LogInfo("shutting down HTTP/2 server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
		}
	})
	defer func() {
		if !stopShutdown() {
			<-shutdownDone
		}
	}()

	if err := srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
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
	p.listenerStarted(listenerInternal)
	defer p.listenerState.And(^uint32(listenerInternal))

	stopShutdown := context.AfterFunc(ctx, func() {
		common.LogInfo("shutting down internal gRPC server")
		p.internalGRPCServer.Stop()
	})
	defer stopShutdown()

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
		platformRPC := net.ParseIP(requestHostname(r.Host)) != nil || !p.customerHost(r.Host) && extractTunnelID(requestHostname(r.Host), p.Domain) == ""
		if strings.HasPrefix(contentType, "application/grpc") && platformRPC {
			// Route to gRPC server
			common.LogDebug("routing to gRPC", "path", r.URL.Path, "content-type", contentType)
			p.grpcServer.ServeHTTP(w, publisherRequest(r))
			return
		}

		// Otherwise, route to HTTP handler
		p.advertiseHTTP3(w, r)
		httpHandler.ServeHTTP(w, r)
	})
}

// advertiseHTTP3 makes the QUIC listener discoverable to clients that first
// reach the service over HTTPS/TCP. The configured UDP port must also be
// exposed by the deployment platform.
func (p *ProxyServer) advertiseHTTP3(w http.ResponseWriter, r *http.Request) {
	if p.config != nil && !p.config.HTTP3Enabled() || r.TLS == nil || r.Method == http.MethodConnect {
		return
	}
	_, portText, err := net.SplitHostPort(p.HTTP3Addr)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return
	}
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=3600`, port))
}

// createHandler creates the HTTP handler for both servers
func (p *ProxyServer) createHandler() http.Handler {
	mux := http.NewServeMux()

	// Health check endpoint (no auth required)
	mux.HandleFunc("/health", p.handleHealth)
	mux.HandleFunc("/healthz", p.handleHealth)
	mux.HandleFunc("/readyz", p.handleHealth)
	mux.HandleFunc("/report", p.handleBugReport)
	mux.HandleFunc("/ops/reports", p.handleBugReportsRead)
	mux.HandleFunc("/status", p.handleStatus)
	mux.HandleFunc("/status.json", p.handleStatus)

	// Install script endpoint
	mux.HandleFunc("/install.sh", p.handleInstallScript)
	mux.HandleFunc("/dl/examples/mcp/echo.py", handleMCPEchoExample)
	mux.Handle("/dl/", downloads.Handler())

	// Auth endpoints (no auth required on these)
	mux.HandleFunc("/auth/domain", p.handleDomainLogin)
	mux.HandleFunc("/.well-known/tunn-jwks.json", p.handleIdentityJWKS)
	mux.HandleFunc("/auth/login", p.handleLogin)
	mux.HandleFunc("/auth/github", p.handleGitHubLogin)
	mux.HandleFunc("/auth/google", p.handleGoogleLogin)
	mux.HandleFunc("/auth/google/callback", p.handleGoogleCallback)
	mux.HandleFunc("/auth/org/", p.handleOrgOIDC)
	mux.HandleFunc("/auth/mock", p.handleMockLogin)
	mux.HandleFunc("/auth/callback", p.handleCallback)
	mux.HandleFunc("/auth/magic", p.handleMagicLinkRequest)
	mux.HandleFunc("/auth/verify", p.handleMagicLinkVerify)
	mux.HandleFunc("/auth/logout", p.handleLogout)

	// Account page (requires auth)
	mux.HandleFunc("/account", p.handleAccount)
	mux.HandleFunc("/account/names", p.handleAccountNames)
	mux.HandleFunc("/api/account/tunnels", p.handleAccountTunnels)
	mux.HandleFunc("/account/audit", p.handleAudit)
	mux.HandleFunc("/account/audit.csv", p.handleAudit)
	mux.HandleFunc("/account/audit.json", p.handleAudit)
	mux.HandleFunc("/api/account/audit/", p.handleAudit)
	mux.HandleFunc("/account/emails", p.handleAccountEmails)
	mux.HandleFunc("/account/tunnel-alerts", p.handleTunnelAlertSettings)
	mux.HandleFunc("/account/inspect", p.handleInspectorPage)
	mux.HandleFunc("/api/inspector/", p.handleInspectorAPI)
	mux.HandleFunc("/about", p.handleAbout)
	mux.HandleFunc("/pricing", p.handlePricing)
	mux.HandleFunc("/ngrok-alternative", p.handleComparison)
	mux.HandleFunc("/upgrade", p.handleUpgrade)
	mux.HandleFunc("/api/billing/status", p.handleBillingStatus)
	mux.HandleFunc("/docs", p.handleDocs)
	mux.HandleFunc("/docs/", p.handleDocs)
	mux.HandleFunc("/account/mcp", p.handleMCPOAuth)
	mux.HandleFunc("/api/mcp/clients", p.handleMCPOAuth)
	mux.HandleFunc("/.well-known/oauth-authorization-server", p.handleMCPOAuth)
	mux.HandleFunc("/oauth/", p.handleMCPOAuth)

	mux.HandleFunc("/api/hosts", p.handleHosts)
	mux.HandleFunc("/api/ssh/keys", p.handleSSHKeys)
	mux.HandleFunc("/auth/ssh-key", p.handleSSHKeyLink)

	// Device code flow for CLI login
	mux.HandleFunc("/api/device/code", p.handleDeviceCode)
	mux.HandleFunc("/api/device/token", p.handleDeviceToken)
	mux.HandleFunc("/api/device/refresh", p.handleDeviceRefresh)
	mux.HandleFunc("/account/devices", p.handleDevices)
	mux.HandleFunc("/account/app-devices", p.handleAppDevices)
	mux.HandleFunc("/pair/app-device", p.handleAppDevices)
	mux.HandleFunc("/api/app-devices", p.handleAppDevices)
	mux.HandleFunc("/api/app-devices/", p.handleAppDevices)
	mux.HandleFunc("/api/endpoints/", p.handleMeteringAPI)
	mux.HandleFunc("/api/ip-policy", p.handleIPPolicyAPI)
	mux.HandleFunc("/api/ip-policy/", p.handleIPPolicyAPI)
	mux.HandleFunc("/account/ip-policy", p.handleIPPolicyPage)
	mux.HandleFunc("/api/sharing", p.handleSharingAPI)
	mux.HandleFunc("/api/sharing/", p.handleSharingAPI)
	mux.HandleFunc("/account/sharing", p.handleSharingPage)
	mux.HandleFunc("/api/usage", p.handleMeteringAPI)
	mux.HandleFunc("/api/grants", p.handleMeteringAPI)
	mux.HandleFunc("/api/domains/publisher", p.handleNamespacePublisher)
	mux.HandleFunc("/api/domains", p.handleDomainsAPI)
	mux.HandleFunc("/api/domains/", p.handleDomainsAPI)
	mux.HandleFunc("/api/reports", p.handleReportIntake)
	mux.HandleFunc("/login", p.handleLoginPage)
	mux.HandleFunc("/auth/device/authorize", p.handleDeviceAuthorize)

	// Stripe webhook endpoint
	mux.HandleFunc("/webhooks/stripe", p.handleStripeWebhook)

	// Main handler - check if this is apex domain or a tunnel subdomain
	mux.HandleFunc("/", p.handleWebProxy)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.protectedResponse(r) {
			w = protectResponse(w)
		}
		if isAppCredentialAttempt(r) && !p.customerHost(r.Host) {
			appAuthenticationError(w, 401)
			return
		}
		// Publishers own every path on their tunnel origin. Serving platform
		// forms there would let their scripts read session-bound CSRF tokens.
		if p.customerHost(r.Host) && r.URL.Path == appCallback {
			p.handleDomainCallback(w, r)
			return
		}
		if p.customerHost(r.Host) && r.URL.Path == "/.tunn/devices" && r.Method == http.MethodGet && len(appHeaderValues(r.Header, "Tunn-Authorization")) == 0 && !isAppCredentialAttempt(r) {
			http.Redirect(w, r, "https://"+p.loginAuthority()+"/account/app-devices?host="+url.QueryEscape(requestHostname(r.Host)), 302)
			return
		}
		if p.customerHost(r.Host) || extractTunnelID(requestHostname(r.Host), p.Domain) != "" {
			if !p.customerHost(r.Host) && (r.URL.Path == "/.well-known/oauth-protected-resource/mcp" || r.URL.Path == "/.well-known/oauth-protected-resource") {
				p.handleMCPResourceMetadata(w, r, extractTunnelID(requestHostname(r.Host), p.Domain))
				return
			}
			p.handleWebProxy(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/auth/") || r.URL.Path == "/login" || r.URL.Path == "/account" || r.URL.Path == "/upgrade" || r.URL.Path == "/api/billing/status" || strings.HasPrefix(r.URL.Path, "/api/device/") {
			if !p.isPlatformHost(r.Host) {
				http.Error(w, "Invalid authentication host", http.StatusForbidden)
				return
			}
		}
		// HTTP/2 CONNECT is authority-form and arrives without a URL path. An
		// empty path does not match ServeMux's "/" pattern, so raw tunnel
		// connections must enter the subdomain router before mux dispatch.
		if r.Method == http.MethodConnect {
			p.handleWebProxy(w, r)
			return
		}
		if p.statusUnconfigured() && !strings.HasPrefix(r.URL.Path, "/dl/") {
			w = &statusLinksHiddenWriter{ResponseWriter: w}
		}
		mux.ServeHTTP(w, r)
	})
}

// handleInstallScript serves the install script for curl | sh installation
func (p *ProxyServer) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	ua := r.Header.Get("User-Agent")
	ip := extractClientIP(r)
	common.LogInfo("install script download", "ip", ip, "ua", ua)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprint(w, installScript)
}

var installScript = downloads.Installer()

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
	return p.findAndConnectLoginNodeContext(context.Background())
}

func (p *ProxyServer) findAndConnectLoginNodeContext(parent context.Context) bool {
	pause := func() bool {
		timer := time.NewTimer(500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-parent.Done():
			return false
		case <-timer.C:
			return true
		}
	}

	// Query each peer to find the login node (with delay between queries)
	for addr, client := range p.nodeClients {
		if parent.Err() != nil {
			return false
		}
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		resp, err := client.GetNodeInfo(ctx, &internalv1.NodeInfoRequest{})
		cancel()

		if err != nil {
			common.LogError("failed to get node info", "addr", addr, "error", err)
			if !pause() {
				return false
			}
			continue
		}

		if resp.IsLoginNode {
			// Found the login node
			common.LogInfo("discovered login node", "addr", addr, "node_id", resp.NodeId)

			// Create a dedicated connection to the login node
			conn, err := createInternalClient(addr, p.config)
			if err != nil {
				common.LogError("failed to connect to login node", "addr", addr, "error", err)
				if !pause() {
					return false
				}
				continue
			}
			if parent.Err() != nil {
				_ = conn.Close()
				return false
			}

			// Close existing connection if any
			p.loginNodeMu.Lock()
			if p.loginNodeConn != nil {
				_ = p.loginNodeConn.Close()
			}

			p.loginNodeConn = conn
			p.loginNodeClient = internalv1.NewInternalServiceClient(conn)
			p.loginNodeHTTPAddr = resp.NodeId

			// Update proxy storage connection (for non-login nodes)
			if p.proxyStorage != nil {
				p.proxyStorage.SetConnection(conn)
				common.LogInfo("proxy storage connected to login node")
			}
			p.loginNodeMu.Unlock()

			return true
		}

		if !pause() {
			return false
		}
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
		if p.findAndConnectLoginNodeContext(ctx) {
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

// usageFlushLoop periodically flushes buffered usage to the login node.
// Runs on non-login nodes only.
func (p *ProxyServer) usageFlushLoop(ctx context.Context) {
	// Flush every 10 seconds, or immediately when login node reconnects
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Cleanup quota cache periodically (entries older than 5 minutes)
	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush attempt on shutdown
			if p.usageBuffer.Len() > 0 && p.storage.Available() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				flushed, _ := p.usageBuffer.Flush(shutdownCtx, p.storage)
				cancel()
				if flushed > 0 {
					common.LogInfo("flushed usage on shutdown", "accounts", flushed)
				}
			}
			return

		case <-ticker.C:
			if p.usageBuffer.Len() > 0 && p.storage.Available() {
				flushed, err := p.usageBuffer.Flush(ctx, p.storage)
				if err != nil {
					common.LogError("usage flush failed", "error", err)
				} else if flushed > 0 {
					common.LogInfo("flushed buffered usage", "accounts", flushed)
				}
			}

		case <-cleanupTicker.C:
			removed := p.quotaCache.Cleanup(5 * time.Minute)
			if removed > 0 {
				common.LogDebug("cleaned up quota cache", "removed", removed)
			}
		}
	}
}

// RecordUsage records bandwidth usage with graceful degradation.
// If storage is available, records directly. Otherwise buffers locally.
// Triggers immediate flush if buffered usage exceeds threshold (20 MB).
func (p *ProxyServer) RecordUsage(ctx context.Context, accountID string, bytes int64) {
	if p.storage.Available() {
		if err := p.storage.RecordUsage(ctx, accountID, bytes); err != nil {
			// Storage call failed - buffer instead
			common.LogError("failed to record usage, buffering", "account_id", accountID, "bytes", bytes, "error", err)
			if p.usageBuffer.Add(accountID, bytes) {
				// Threshold exceeded - try to flush immediately
				go p.flushUsageBuffer(ctx)
			}
		}
		return
	}

	// Storage not available - buffer locally
	if p.usageBuffer.Add(accountID, bytes) {
		// Threshold exceeded - try to flush (will retry if storage becomes available)
		go p.flushUsageBuffer(ctx)
	}
}

// flushUsageBuffer attempts to flush buffered usage to storage.
func (p *ProxyServer) flushUsageBuffer(ctx context.Context) {
	if !p.storage.Available() {
		return
	}
	flushed, err := p.usageBuffer.Flush(ctx, p.storage)
	if err != nil {
		common.LogError("threshold flush failed", "error", err)
	} else if flushed > 0 {
		common.LogInfo("threshold flush completed", "accounts", flushed)
	}
}

// CheckQuota checks if an account is within its usage quota.
// Unknown identities, storage failures, and unavailable usage data fail closed.
func (p *ProxyServer) CheckQuota(ctx context.Context, accountID string, _ string) bool {
	if accountID == "" || p.storage == nil || !p.storage.Available() {
		return false
	}
	account, err := p.storage.GetAccount(ctx, accountID)
	if err != nil || account == nil || account.ID == "" || account.OperationalState != "active" {
		return false
	}
	return p.checkQuota(ctx, account.ID, account.Plan)
}

// The caller supplies a freshly resolved account, never a tunnel's plan snapshot.
func (p *ProxyServer) checkQuota(ctx context.Context, accountID, plan string) bool {
	// Get quota limit based on plan (defined in limits.go)
	quotaBytes := GetQuotaBytes(plan)
	// Read buffered usage before the storage query: a concurrent flush may
	// already appear in the database, but cannot make prior usage disappear.
	var pending int64
	if p.usageBuffer != nil {
		for id, bytes := range p.usageBuffer.Snapshot() {
			if id != accountID {
				account, err := p.storage.GetAccount(ctx, id)
				if err != nil {
					return false
				}
				if account == nil || account.ID != accountID {
					continue
				}
			}
			if bytes < 0 || pending > quotaBytes-bytes {
				return false
			}
			pending += bytes
		}
	}
	usage, err := p.storage.GetMonthlyUsage(ctx, accountID)
	if err != nil {
		common.LogError("failed to verify quota, rejecting traffic", "account_id", accountID, "error", err)
		return false
	}
	if p.quotaCache != nil {
		p.quotaCache.Set(accountID, usage)
	}
	return usage >= 0 && pending >= 0 && usage < quotaBytes && pending < quotaBytes-usage
}
