package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/host"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
)

// Global flags (parsed before subcommand)
var (
	verbosity  = flag.String("verbosity", "request", "log level: none, error, request, trace")
	skipVerify = flag.Bool("skip-tls-verify", false, "skip TLS certificate verification (insecure)")

	// Hidden flag for server operators
	mode = flag.String("mode", "", "internal: host mode for server operators")

	// Host mode flags
	domain   = flag.String("domain", "tunn.to", "public apex domain")
	certFile = flag.String("cert", "/app/certs/fullchain.pem", "TLS certificate file (host mode)")
	keyFile  = flag.String("key", "/app/certs/privkey.pem", "TLS private key file (host mode)")
)

func main() {
	// Load .env file if present (silently ignored if not found)
	_ = godotenv.Load()

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `tunn - expose localhost to the internet

Usage:
  tunn <port>                    Tunnel localhost:<port> to a public URL
  tunn <host:port>               Tunnel host:port to a public URL
  tunn <url>                     Tunnel any URL to a public URL
  tunn login                     Authenticate with GitHub
  tunn serve [options] <target>  Explicit serve mode (same as default)

Examples:
  tunn 8080                              # https://abc123.tunn.to -> localhost:8080
  tunn 8080 --allow alice@gmail.com      # Share with specific people
  tunn localhost:3000                    # Tunnel localhost:3000
  tunn http://api.local:9000             # Tunnel any URL

Options:
`)
		flag.PrintDefaults()
	}

	// Parse global flags first, but stop at first non-flag
	flag.Parse()
	args := flag.Args()

	// Setup logging
	logLevel := common.ParseLogLevel(*verbosity)
	common.SetLogLevel(logLevel)

	// Handle hidden -mode=host for server operators
	if *mode == "host" {
		runHost()
		return
	}

	// No args? Show help
	if len(args) == 0 {
		flag.Usage()
		os.Exit(0)
	}

	// Route to subcommand or default serve behavior
	switch args[0] {
	case "login":
		runLogin()
	case "serve":
		runServe(args[1:])
	case "magic-link":
		runMagicLink(args[1:])
	case "help", "-h", "--help":
		flag.Usage()
		os.Exit(0)
	default:
		// Default: treat first arg as target, rest as flags
		runServe(args)
	}
}

// Serve subcommand flags
func parseServeFlags(args []string) (target string, tunnelID string, allowedEmails []string, tunnelKey string, clientSecret string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	idFlag := fs.String("id", "", "tunnel ID (blank → random)")
	subdomainFlag := fs.String("subdomain", "", "reserved subdomain (Pro feature, alias for -id)")
	allowFlag := fs.String("allow", "", "comma-separated list of emails allowed to access tunnel")
	keyFlag := fs.String("tunnel-key", "", "tunnel creation authorization key")
	secretFlag := fs.String("secret", "", "client secret for auth (or set TUNN_SECRET env var)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `tunn serve - expose localhost to the internet

Usage:
  tunn serve [options] <target>
  tunn <target>                  (shorthand)

Examples:
  tunn 8080                         # Tunnel localhost:8080
  tunn 8080 --allow bob@co.com      # Share with specific people
  tunn serve --id=myapp 3000        # Custom tunnel ID
  tunn serve --subdomain=myapp 3000 # Reserved subdomain (Pro)

Options:
`)
		fs.PrintDefaults()
	}

	// Find target (non-flag arg)
	var nonFlagArgs []string
	var flagArgs []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
		} else {
			nonFlagArgs = append(nonFlagArgs, arg)
		}
	}

	// Parse just the flags
	fs.Parse(flagArgs)

	if len(nonFlagArgs) == 0 {
		common.LogError("target required: tunn <port|host:port|url>")
		fs.Usage()
		os.Exit(1)
	}

	target = nonFlagArgs[0]
	// --subdomain takes precedence over --id (they're effectively the same)
	tunnelID = *idFlag
	if *subdomainFlag != "" {
		tunnelID = *subdomainFlag
	}
	tunnelKey = *keyFlag

	// Client secret: flag takes precedence, then env var
	clientSecret = *secretFlag
	if clientSecret == "" {
		clientSecret = os.Getenv("TUNN_SECRET")
	}

	if *allowFlag != "" {
		emails := strings.Split(*allowFlag, ",")
		for _, email := range emails {
			allowedEmails = append(allowedEmails, strings.TrimSpace(email))
		}
	}

	return
}

func runLogin() {
	cfg, err := config.LoadConfig()
	if err != nil {
		common.LogError("failed to load config", "error", err)
		os.Exit(1)
	}

	loginClient := &client.LoginClient{
		ServerAddr: cfg.ServerAddr,
		SkipVerify: cfg.SkipVerify || *skipVerify,
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
}

func runHost() {
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

	proxy, err := host.NewProxyServer(cfg)
	if err != nil {
		common.LogError("failed to create proxy server", "error", err)
		os.Exit(1)
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

	if err := proxy.Run(ctx); err != nil && err != context.Canceled {
		common.LogError("proxy server error", "error", err)
		os.Exit(1)
	}
}

func runServe(args []string) {
	target, tunnelID, allowedEmails, tunnelKey, clientSecret := parseServeFlags(args)

	cfg, err := config.LoadConfig()
	if err != nil {
		common.LogError("failed to load config", "error", err)
		os.Exit(1)
	}

	// Determine auth token: client secret OR JWT from login
	var token string
	if clientSecret != "" {
		// Use client secret as auth token (self-hosters)
		token = clientSecret
	} else if !cfg.PublicMode {
		// Load JWT from token file
		token, err = client.LoadToken()
		if err != nil {
			common.LogError("not logged in - run 'tunn login' first, or use --secret for self-hosted servers", "error", err)
			os.Exit(1)
		}
	}

	// Get tunnel key from flag or env var
	if tunnelKey == "" {
		tunnelKey = cfg.WellKnownKey
		if tunnelKey == "" {
			common.LogError("tunnel key not provided - use --tunnel-key or set WELL_KNOWN_KEY env var")
			os.Exit(1)
		}
	}

	// Generate tunnel ID if not provided
	if tunnelID == "" {
		tunnelID = common.RandID(7)
	}

	// Normalize target URL
	normalizedTarget, err := normalizeTargetURL(target)
	if err != nil {
		common.LogError("invalid target", "error", err)
		os.Exit(1)
	}

	serveClient := &client.ServeClient{
		TunnelID:      tunnelID,
		TargetURL:     normalizedTarget,
		ServerAddr:    cfg.ServerAddr,
		AuthToken:     token,
		TunnelKey:     tunnelKey,
		AllowedEmails: allowedEmails,
		SkipVerify:    cfg.SkipVerify || *skipVerify,
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

	if err := serveClient.Run(ctx); err != nil && err != context.Canceled {
		common.LogError("tunnel error", "error", err)
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

func runMagicLink(args []string) {
	fs := flag.NewFlagSet("magic-link", flag.ExitOnError)
	secretFlag := fs.String("secret", "", "JWT signing secret (or set TUNN_JWT_SECRET env var)")
	domainFlag := fs.String("domain", "", "domain for full URL output (e.g., tunn.to)")
	expiryFlag := fs.Duration("expiry", 5*time.Minute, "token expiry duration")
	tokenOnlyFlag := fs.Bool("token-only", false, "output only the token, not the full URL")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `tunn magic-link - generate a magic link token for email authentication

Usage:
  tunn magic-link [options] <email>

Examples:
  tunn magic-link alice@example.com                       # Token only (uses TUNN_JWT_SECRET)
  tunn magic-link --secret=mysecret alice@example.com     # With explicit secret
  tunn magic-link --domain=tunn.to alice@example.com      # Full URL output

Options:
`)
		fs.PrintDefaults()
	}

	// Separate flags from positional args
	var nonFlagArgs []string
	var flagArgs []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
		} else {
			nonFlagArgs = append(nonFlagArgs, arg)
		}
	}

	fs.Parse(flagArgs)

	if len(nonFlagArgs) == 0 {
		common.LogError("email required: tunn magic-link <email>")
		fs.Usage()
		os.Exit(1)
	}

	email := strings.ToLower(strings.TrimSpace(nonFlagArgs[0]))
	if !strings.Contains(email, "@") {
		common.LogError("invalid email address", "email", email)
		os.Exit(1)
	}

	// Get secret from flag or env
	secret := *secretFlag
	if secret == "" {
		secret = os.Getenv("TUNN_JWT_SECRET")
	}
	if secret == "" {
		common.LogError("JWT secret required: use -secret flag or set TUNN_JWT_SECRET env var")
		os.Exit(1)
	}

	// Generate JTI for replay protection
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		common.LogError("failed to generate JTI", "error", err)
		os.Exit(1)
	}
	jti := hex.EncodeToString(jtiBytes)

	// Generate magic link token with JTI for replay protection
	claims := jwt.MapClaims{
		"jti":   jti,
		"email": email,
		"type":  "magic_link",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(*expiryFlag).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		common.LogError("failed to sign token", "error", err)
		os.Exit(1)
	}

	// Output
	if *tokenOnlyFlag || *domainFlag == "" {
		fmt.Println(tokenString)
	} else {
		fmt.Printf("https://%s/auth/verify?token=%s\n", *domainFlag, tokenString)
	}
}
