package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/host"
)

var (
	mode       = flag.String("mode", "client", "host | client | login")
	to         = flag.String("to", "http://127.0.0.1:8000", "target to forward to (port, host:port, or full URL)")
	id         = flag.String("id", "", "tunnel ID (client); blank → random")
	domain     = flag.String("domain", "tunn.to", "public apex domain")
	verbosity  = flag.String("verbosity", "request", "log level: none, error, request, trace")
	skipVerify = flag.Bool("skip-tls-verify", false, "skip TLS certificate verification (insecure)")
	certFile   = flag.String("cert", "/app/certs/fullchain.pem", "TLS certificate file (host mode)")
	keyFile    = flag.String("key", "/app/certs/privkey.pem", "TLS private key file (host mode)")

	// Client mode flags
	allow     = flag.String("allow", "", "comma-separated list of emails allowed to access tunnel (client mode)")
	tunnelKey = flag.String("tunnel-key", "", "tunnel creation authorization key (client mode); defaults to WELL_KNOWN_KEY env var")
)

func main() {
	flag.Parse()

	// Setup logging
	logLevel := common.ParseLogLevel(*verbosity)
	common.SetLogLevel(logLevel)

	switch *mode {
	case "login":
		// Login mode doesn't require TOKEN
		cfg, err := config.LoadConfig()
		if err != nil {
			common.LogError("failed to load config", "error", err)
			os.Exit(1)
		}

		loginClient := &client.LoginClient{
			ServerAddr: cfg.ServerAddr,
			OIDCIssuer: cfg.MockOIDCIssuer,
			SkipVerify: cfg.SkipVerify,
		}

		// Use production OIDC if not in dev mode
		if !cfg.IsDev() {
			loginClient.OIDCIssuer = "https://accounts.google.com"
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigChan
			common.LogInfo("received shutdown signal")
			cancel()
		}()

		if err := loginClient.Run(ctx); err != nil && err != context.Canceled {
			common.LogError("login failed", "error", err)
			os.Exit(1)
		}
	case "host":
		// Host mode requires TOKEN
		token := os.Getenv("TOKEN")
		if token != "" {
			common.LogInfo("using token from environment variable")
		} else {
			common.LogError("TOKEN environment variable not set")
			os.Exit(1)
		}
		runHost(token)
	case "client":
		// Client mode loads JWT from token file
		runClient()
	default:
		common.LogError("invalid mode", "mode", *mode)
		os.Exit(1)
	}
}

func runHost(token string) {
	// Load config and override with flags
	cfg, err := config.LoadConfig()
	if err != nil {
		common.LogError("failed to load config", "error", err)
		os.Exit(1)
	}

	// Override config with flags if provided
	if *domain != "tunn.to" {
		cfg.Domain = *domain
	}
	if *certFile != "/app/certs/fullchain.pem" {
		cfg.CertFile = *certFile
	}
	if *keyFile != "/app/certs/privkey.pem" {
		cfg.KeyFile = *keyFile
	}

	// Create proxy server
	proxy, err := host.NewProxyServer(cfg)
	if err != nil {
		common.LogError("failed to create proxy server", "error", err)
		os.Exit(1)
	}

	// Set up context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		common.LogInfo("received shutdown signal")
		cancel()
	}()

	// Run proxy server
	if err := proxy.Run(ctx); err != nil && err != context.Canceled {
		common.LogError("proxy server error", "error", err)
		os.Exit(1)
	}
}

func runClient() {
	// Load config for server address
	cfg, err := config.LoadConfig()
	if err != nil {
		common.LogError("failed to load config", "error", err)
		os.Exit(1)
	}

	// Load JWT from token file (skip in public mode)
	var token string
	if !cfg.PublicMode {
		token, err = client.LoadToken()
		if err != nil {
			common.LogError("failed to load JWT token - run 'tunn login' first", "error", err)
			os.Exit(1)
		}
	} else {
		common.LogInfo("public mode - skipping JWT load")
		token = "" // No token needed in public mode
	}

	// Get tunnel key from flag or env var
	key := *tunnelKey
	if key == "" {
		key = cfg.WellKnownKey
		if key == "" {
			common.LogError("tunnel key not provided - use -tunnel-key or set WELL_KNOWN_KEY env var")
			os.Exit(1)
		}
	}

	// Parse allowed emails from comma-separated list
	var allowedEmails []string
	if *allow != "" {
		allowedEmails = strings.Split(*allow, ",")
		// Trim whitespace from each email
		for i, email := range allowedEmails {
			allowedEmails[i] = strings.TrimSpace(email)
		}
	}

	// Generate tunnel ID if not provided
	tunnelID := *id
	if tunnelID == "" {
		tunnelID = common.RandID(7)
	}

	// Normalize target URL
	normalizedTo, err := normalizeTargetURL(*to)
	if err != nil {
		common.LogError("invalid target URL", "error", err)
		os.Exit(1)
	}

	// Create serve client
	serveClient := &client.ServeClient{
		TunnelID:      tunnelID,
		TargetURL:     normalizedTo,
		ServerAddr:    cfg.ServerAddr,
		AuthToken:     token,
		TunnelKey:     key,
		AllowedEmails: allowedEmails,
		SkipVerify:    cfg.SkipVerify,
	}

	// Override SkipVerify if flag was explicitly set
	if *skipVerify {
		serveClient.SkipVerify = true
	}

	common.LogInfo("tunnel configuration",
		"id", tunnelID,
		"target", normalizedTo,
		"allowed_emails", allowedEmails,
		"tunnel_key", key)

	// Set up context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		common.LogInfo("received shutdown signal")
		cancel()
	}()

	// Run serve client
	if err := serveClient.Run(ctx); err != nil && err != context.Canceled {
		common.LogError("serve client error", "error", err)
		os.Exit(1)
	}
}

// normalizeTargetURL converts various input formats to a full URL
// Accepts: "8000", "localhost:8000", "http://localhost:8000"
// Always returns: "http://localhost:8000" format
func normalizeTargetURL(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty target")
	}

	// If it's already a full URL, validate and return
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		return input, nil
	}

	// Check if it's "host:port" format
	if strings.Contains(input, ":") {
		return "http://" + input, nil
	}

	// Check if it's just a port number
	for _, char := range input {
		if char < '0' || char > '9' {
			return "", fmt.Errorf("invalid format: %s (expected port, host:port, or full URL)", input)
		}
	}

	// It's just a port number
	return "http://localhost:" + input, nil
}
