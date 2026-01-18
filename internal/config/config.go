package config

import (
	"fmt"
	"os"
)

// Environment represents the deployment environment
type Environment string

const (
	EnvDev  Environment = "dev"
	EnvProd Environment = "prod"
)

// Config holds the application configuration
type Config struct {
	Environment Environment

	// Server configuration
	Domain    string
	CertFile  string
	KeyFile   string
	HTTP2Addr string // HTTP/2 (TCP) listener address
	HTTP3Addr string // HTTP/3 (QUIC) listener address

	// Internal gRPC configuration
	InternalGRPCPort string
	NodeAddresses    string // Comma-separated list of other node addresses (fallback)
	NodeSecret       string // Shared secret for node-to-node authentication
	PublicAddr       string
	FlyAppName       string // Fly.io app name for DNS-based node discovery
	InternalCACert   string // Path to CA cert for internal TLS verification (self-hosters)

	// Mock OIDC configuration (dev only)
	MockOIDCAddr   string
	MockOIDCIssuer string

	// Tunnel creation authorization
	WellKnownKey string // Free tier key that allows anyone to create tunnels

	// Public mode (testing only - disables all auth)
	PublicMode bool

	// GitHub OAuth configuration
	GitHubClientID     string
	GitHubClientSecret string
	JWTSecret          string // Secret for signing our own JWTs

	// Client authentication (self-hosters)
	ClientSecret string // Master key for all clients (bypasses OAuth)
	UsersFile    string // Path to users.yaml for per-user tokens

	// SMTP configuration (for magic link auth)
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string

	// Stripe configuration (for billing)
	StripeWebhookSecret string

	// Client configuration
	ServerAddr string
	SkipVerify bool

	// Login node configuration
	// Login node owns SQLite and handles all DB operations
	// Other nodes proxy DB operations to it
	LoginNode bool
	DBPath    string // Path to SQLite database (login node only)
}

// LoadConfig loads configuration based on environment
func LoadConfig() (*Config, error) {
	env := getEnvironment()

	cfg := &Config{
		Environment: env,
	}

	switch env {
	case EnvDev:
		cfg.loadDevConfig()
	case EnvProd:
		cfg.loadProdConfig()
	default:
		return nil, fmt.Errorf("unknown environment: %s", env)
	}

	return cfg, nil
}

// loadDevConfig loads development configuration
func (c *Config) loadDevConfig() {
	// Use nip.io for local wildcard DNS
	// Format: *.tunn.local.127.0.0.1.nip.io resolves to 127.0.0.1
	c.Domain = getEnvOrDefault("DOMAIN", "tunn.local.127.0.0.1.nip.io")

	// Use local test certificates
	c.CertFile = getEnvOrDefault("CERT_FILE", "./certs/cert.pem")
	c.KeyFile = getEnvOrDefault("KEY_FILE", "./certs/key.pem")

	// HTTP listener address (ADDR sets both, or use HTTP2_ADDR/HTTP3_ADDR for separate control)
	defaultAddr := getEnvOrDefault("ADDR", ":8443")
	c.HTTP2Addr = getEnvOrDefault("HTTP2_ADDR", defaultAddr)
	c.HTTP3Addr = getEnvOrDefault("HTTP3_ADDR", defaultAddr)

	// Internal gRPC
	c.InternalGRPCPort = getEnvOrDefault("INTERNAL_GRPC_PORT", ":50051")
	c.NodeAddresses = getEnvOrDefault("NODE_ADDRESSES", "")
	c.NodeSecret = getEnvOrDefault("NODE_SECRET", "dev-node-secret")
	c.PublicAddr = getEnvOrDefault("PUBLIC_ADDR", "localhost:8443")
	c.FlyAppName = getEnvOrDefault("FLY_APP_NAME", "")     // Fly.io sets this automatically
	c.InternalCACert = getEnvOrDefault("TUNN_CA_CERT", "") // Custom CA for internal TLS (self-hosters)

	// Mock OIDC provider runs locally (set MOCK_OIDC_ADDR="" to disable)
	c.MockOIDCAddr = getEnvAllowEmpty("MOCK_OIDC_ADDR", ":9000")
	c.MockOIDCIssuer = getEnvOrDefault("MOCK_OIDC_ISSUER", "http://localhost:9000")

	// Server address for clients
	c.ServerAddr = getEnvOrDefault("SERVER_ADDR", "localhost:8443")

	// Tunnel creation key (free tier)
	c.WellKnownKey = getEnvOrDefault("WELL_KNOWN_KEY", "tunn-free-v1-2025")

	// Public mode (disable all auth for testing)
	c.PublicMode = getEnvOrDefault("PUBLIC_MODE", "") == "true"

	// GitHub OAuth (optional in dev - uses mock OIDC if not set)
	c.GitHubClientID = getEnvOrDefault("GITHUB_CLIENT_ID", "")
	c.GitHubClientSecret = getEnvOrDefault("GITHUB_CLIENT_SECRET", "")
	c.JWTSecret = getEnvOrDefault("JWT_SECRET", "dev-jwt-secret-do-not-use-in-prod")

	// Client secret (self-hosters can bypass OAuth with this)
	c.ClientSecret = getEnvOrDefault("CLIENT_SECRET", "")
	c.UsersFile = getEnvOrDefault("USERS_FILE", "")

	// SMTP (optional in dev)
	c.SMTPHost = getEnvOrDefault("SMTP_HOST", "")
	c.SMTPPort = getEnvOrDefault("SMTP_PORT", "587")
	c.SMTPUser = getEnvOrDefault("SMTP_USER", "")
	c.SMTPPassword = getEnvOrDefault("SMTP_PASSWORD", "")
	c.SMTPFrom = getEnvOrDefault("SMTP_FROM", "")

	// Stripe (optional in dev)
	c.StripeWebhookSecret = getEnvOrDefault("STRIPE_WEBHOOK_SECRET", "")

	// Skip TLS verification in dev
	c.SkipVerify = true

	// Login node (defaults to true in dev for simplicity)
	c.LoginNode = IsLoginNode() || getEnvOrDefault("LOGIN_NODE", "true") == "true"
	c.DBPath = getEnvOrDefault("TUNN_DB_PATH", "")
}

// loadProdConfig loads production configuration
func (c *Config) loadProdConfig() {
	// Production domain
	c.Domain = getEnvOrDefault("DOMAIN", "tunn.to")

	// Production certificates (Fly.io paths)
	c.CertFile = getEnvOrDefault("CERT_FILE", "/app/certs/fullchain.pem")
	c.KeyFile = getEnvOrDefault("KEY_FILE", "/app/certs/privkey.pem")

	// HTTP listener address (ADDR sets both, or use HTTP2_ADDR/HTTP3_ADDR for separate control)
	prodDefaultAddr := getEnvOrDefault("ADDR", ":8443")
	c.HTTP2Addr = getEnvOrDefault("HTTP2_ADDR", prodDefaultAddr)
	c.HTTP3Addr = getEnvOrDefault("HTTP3_ADDR", prodDefaultAddr)

	// Internal gRPC
	c.InternalGRPCPort = getEnvOrDefault("INTERNAL_GRPC_PORT", ":50051")
	c.NodeAddresses = getEnvOrDefault("NODE_ADDRESSES", "")
	c.NodeSecret = getEnvOrDefault("NODE_SECRET", "") // Must be set in prod for multi-node
	c.PublicAddr = getEnvOrDefault("PUBLIC_ADDR", "tunn.to:443")
	c.FlyAppName = getEnvOrDefault("FLY_APP_NAME", "")     // Fly.io sets this automatically
	c.InternalCACert = getEnvOrDefault("TUNN_CA_CERT", "") // Custom CA for internal TLS (self-hosters)

	// No mock OIDC in production
	c.MockOIDCAddr = ""
	c.MockOIDCIssuer = ""

	// Server address for clients
	c.ServerAddr = getEnvOrDefault("SERVER_ADDR", "tunn.to:443")

	// Tunnel creation key (free tier)
	c.WellKnownKey = getEnvOrDefault("WELL_KNOWN_KEY", "tunn-free-v1-2025")

	// GitHub OAuth (required in prod for tunn.to)
	c.GitHubClientID = getEnvOrDefault("GITHUB_CLIENT_ID", "")
	c.GitHubClientSecret = getEnvOrDefault("GITHUB_CLIENT_SECRET", "")
	c.JWTSecret = getEnvOrDefault("JWT_SECRET", "") // Must be set in prod

	// Client secret (self-hosters only - tunn.to leaves this empty)
	c.ClientSecret = getEnvOrDefault("CLIENT_SECRET", "")
	c.UsersFile = getEnvOrDefault("USERS_FILE", "")

	// SMTP (for magic link auth)
	c.SMTPHost = getEnvOrDefault("SMTP_HOST", "")
	c.SMTPPort = getEnvOrDefault("SMTP_PORT", "587")
	c.SMTPUser = getEnvOrDefault("SMTP_USER", "")
	c.SMTPPassword = getEnvOrDefault("SMTP_PASSWORD", "")
	c.SMTPFrom = getEnvOrDefault("SMTP_FROM", "")

	// Stripe (for billing)
	c.StripeWebhookSecret = getEnvOrDefault("STRIPE_WEBHOOK_SECRET", "")

	// Verify TLS in production
	c.SkipVerify = false

	// Login node (must be explicitly configured in prod)
	c.LoginNode = IsLoginNode()
	c.DBPath = getEnvOrDefault("TUNN_DB_PATH", "/data/tunn.db")
}

// IsDev returns true if running in development environment
func (c *Config) IsDev() bool {
	return c.Environment == EnvDev
}

// IsProd returns true if running in production environment
func (c *Config) IsProd() bool {
	return c.Environment == EnvProd
}

// IsLoginNode returns true if this node is the login node.
// Login node owns SQLite and handles all auth/account operations.
// Determined by:
//   - LOGIN_NODE=true env var (self-host)
//   - FLY_PROCESS_GROUP=login (Fly.io automatic)
func IsLoginNode() bool {
	if os.Getenv("LOGIN_NODE") == "true" {
		return true
	}
	if os.Getenv("FLY_PROCESS_GROUP") == "login" {
		return true
	}
	return false
}

// getEnvironment determines the current environment
func getEnvironment() Environment {
	env := os.Getenv("ENV")
	switch env {
	case "dev", "development":
		return EnvDev
	case "prod", "production":
		return EnvProd
	default:
		// Default to dev for safety
		return EnvDev
	}
}

// getEnvOrDefault retrieves an environment variable or returns a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvAllowEmpty returns the env var value even if empty, only using default if unset
func getEnvAllowEmpty(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
