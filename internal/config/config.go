package config

import (
	"fmt"
	"os"
	"strconv"
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

	// SSH front door (opt-in, login nodes own the key registry).
	SSHHostKeyFile string
	SSHAddr        string // optional separate raw SSH listener, for example :22

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

	// Experimental persistent machine registry (single login relay only).
	HostModeEnabled bool

	// GitHub OAuth configuration
	GoogleClientID     string
	GoogleClientSecret string
	OIDCOrgs           []OIDCOrg // Administrator-controlled organization sign-in and group mappings.
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
	StripeSecretKey          string // Stripe secret key (sk_...) for API calls
	StripeWebhookSecret      string
	StripeCheckoutURLMonthly string // Payment link for monthly Pro
	StripeCheckoutURLYearly  string // Payment link for yearly Pro
	StripePortalURL          string // Customer portal for managing subscriptions
	BillingEnabled           bool   // Explicitly enable checkout after fulfillment acceptance
	ProMonthlyUSD            int    // Display must match the approved Stripe Price
	ProYearlyUSD             int

	// Client configuration
	ServerAddr string
	Insecure   bool

	// Login node configuration
	// Login node owns SQLite and handles all DB operations
	// Other nodes proxy DB operations to it
	LoginNode            bool
	DBPath               string // Path to SQLite database (login node only)
	OwnerMonthlyRequests int64  // optional tighter shared transport admission cap per owner
	OwnerMonthlyBytes    int64  // optional tighter shared transport byte cap per owner
	IdentityKeysFile     string // Ed25519 JWK ring, active key and retained public keys
	CustomDomainsEnabled bool
	HTTP01Addr           string
	ACMEDirectory        string
	ACMEEmail            string
	DomainKeySecret      string // base64-encoded AES-256 key; login node only
}

// LoadConfig loads configuration based on environment
func LoadConfig() (*Config, error) {
	env := getEnvironment()

	cfg := &Config{
		Environment: env,
	}

	cfg.HostModeEnabled = os.Getenv("TUNN_HOST_MODE") == "true"
	cfg.SSHHostKeyFile = os.Getenv("TUNN_SSH_HOST_KEY_FILE")
	cfg.SSHAddr = os.Getenv("TUNN_SSH_ADDR")

	switch env {
	case EnvDev:
		cfg.loadDevConfig()
	case EnvProd:
		cfg.loadProdConfig()
	default:
		return nil, fmt.Errorf("TUNN_ENV must be dev, development, prod, or production")
	}
	for _, budget := range []struct {
		name  string
		value *int64
	}{{"TUNN_OWNER_MONTHLY_REQUESTS", &cfg.OwnerMonthlyRequests}, {"TUNN_OWNER_MONTHLY_BYTES", &cfg.OwnerMonthlyBytes}} {
		value, err := strconv.ParseInt(getEnvOrDefault(budget.name, "0"), 10, 64)
		if err != nil || value < 0 {
			return nil, fmt.Errorf("%s must be a nonnegative integer", budget.name)
		}
		*budget.value = value
	}
	cfg.BillingEnabled = os.Getenv("TUNN_BILLING_ENABLED") == "true"
	for _, price := range []struct {
		name, fallback string
		value          *int
	}{
		{"TUNN_PRO_MONTHLY_USD", "6", &cfg.ProMonthlyUSD},
		{"TUNN_PRO_YEARLY_USD", "60", &cfg.ProYearlyUSD},
	} {
		value, err := strconv.Atoi(getEnvOrDefault(price.name, price.fallback))
		if err != nil || value < 1 || value > 10000 {
			return nil, fmt.Errorf("%s must be an integer from 1 to 10000", price.name)
		}
		*price.value = value
	}

	cfg.GoogleClientID = os.Getenv("TUNN_GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("TUNN_GOOGLE_CLIENT_SECRET")
	cfg.IdentityKeysFile = os.Getenv("TUNN_IDENTITY_KEYS_FILE")
	if err := cfg.loadOIDCOrgs(os.Getenv("TUNN_OIDC_ORGS_FILE")); err != nil {
		return nil, err
	}
	cfg.CustomDomainsEnabled = os.Getenv("TUNN_CUSTOM_DOMAINS") == "true"
	cfg.HTTP01Addr = getEnvOrDefault("TUNN_HTTP01_ADDR", ":80")
	cfg.ACMEDirectory = getEnvOrDefault("TUNN_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory")
	cfg.ACMEEmail = os.Getenv("TUNN_ACME_EMAIL")
	cfg.DomainKeySecret = os.Getenv("TUNN_DOMAIN_KEY_SECRET")
	if err := cfg.validateSettings(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// loadDevConfig loads development configuration
func (c *Config) loadDevConfig() {
	// Use nip.io for local wildcard DNS
	// Format: *.tunn.local.127.0.0.1.nip.io resolves to 127.0.0.1
	c.Domain = getEnvOrDefault("TUNN_DOMAIN", "tunn.local.127.0.0.1.nip.io")

	// Use local test certificates
	c.CertFile = getEnvOrDefault("TUNN_CERT_FILE", "./certs/cert.pem")
	c.KeyFile = getEnvOrDefault("TUNN_KEY_FILE", "./certs/key.pem")

	// HTTP listener address (TUNN_ADDR sets both, or use TUNN_HTTP2_ADDR/TUNN_HTTP3_ADDR for separate control)
	defaultAddr := getEnvOrDefault("TUNN_ADDR", ":8443")
	c.HTTP2Addr = getEnvOrDefault("TUNN_HTTP2_ADDR", defaultAddr)
	c.HTTP3Addr = getEnvOrDefault("TUNN_HTTP3_ADDR", defaultAddr)

	// Internal gRPC
	c.InternalGRPCPort = getEnvOrDefault("TUNN_INTERNAL_GRPC_PORT", ":50051")
	c.NodeAddresses = getEnvOrDefault("TUNN_NODE_ADDRESSES", "")
	c.NodeSecret = getEnvOrDefault("TUNN_NODE_SECRET", "dev-node-secret")
	c.PublicAddr = getEnvOrDefault("TUNN_PUBLIC_ADDR", "localhost:8443")
	c.FlyAppName = getEnvOrDefault("FLY_APP_NAME", "")     // Fly.io sets this automatically
	c.InternalCACert = getEnvOrDefault("TUNN_CA_CERT", "") // Custom CA for internal TLS (self-hosters)

	// Mock OIDC provider runs locally (set TUNN_MOCK_OIDC_ADDR="" to disable)
	c.MockOIDCAddr = getEnvAllowEmpty("TUNN_MOCK_OIDC_ADDR", ":9000")
	c.MockOIDCIssuer = getEnvOrDefault("TUNN_MOCK_OIDC_ISSUER", "http://localhost:9000")

	// Server address for clients (default to prod even in dev - override with TUNN_SERVER_ADDR for local testing)
	c.ServerAddr = getEnvOrDefault("TUNN_SERVER_ADDR", "tunn.to:443")

	// Tunnel creation key (free tier)
	c.WellKnownKey = getEnvOrDefault("TUNN_WELL_KNOWN_KEY", "tunn-free-v1-2025")

	// Public mode (disable all auth for testing)
	c.PublicMode = getEnvOrDefault("TUNN_PUBLIC_MODE", "") == "true"

	// GitHub OAuth (optional in dev - uses mock OIDC if not set)
	c.GitHubClientID = getEnvOrDefault("TUNN_GITHUB_CLIENT_ID", "")
	c.GitHubClientSecret = getEnvOrDefault("TUNN_GITHUB_CLIENT_SECRET", "")
	c.JWTSecret = getEnvOrDefault("TUNN_JWT_SECRET", "dev-jwt-secret-do-not-use-in-prod")

	// Client secret (self-hosters can bypass OAuth with this)
	c.ClientSecret = getEnvOrDefault("TUNN_CLIENT_SECRET", "")
	c.UsersFile = getEnvOrDefault("TUNN_USERS_FILE", "")

	// SMTP (optional in dev)
	c.SMTPHost = getEnvOrDefault("TUNN_SMTP_HOST", "")
	c.SMTPPort = getEnvOrDefault("TUNN_SMTP_PORT", "587")
	c.SMTPUser = getEnvOrDefault("TUNN_SMTP_USER", "")
	c.SMTPPassword = getEnvOrDefault("TUNN_SMTP_PASSWORD", "")
	c.SMTPFrom = getEnvOrDefault("TUNN_SMTP_FROM", "")

	// Stripe (optional in dev)
	c.StripeSecretKey = getEnvOrDefault("TUNN_STRIPE_SECRET_KEY", "")
	c.StripeWebhookSecret = getEnvOrDefault("TUNN_STRIPE_WEBHOOK_SECRET", "")
	c.StripeCheckoutURLMonthly = getEnvOrDefault("TUNN_STRIPE_CHECKOUT_URL_MONTHLY", "")
	c.StripeCheckoutURLYearly = getEnvOrDefault("TUNN_STRIPE_CHECKOUT_URL_YEARLY", "")
	c.StripePortalURL = getEnvOrDefault("TUNN_STRIPE_PORTAL_URL", "")

	// Skip TLS verification in dev
	c.Insecure = true

	// Login node (defaults to true in dev for simplicity)
	c.LoginNode = IsLoginNode() || getEnvOrDefault("TUNN_LOGIN_NODE", "true") == "true"
	c.DBPath = getEnvOrDefault("TUNN_DB_PATH", "")
}

// loadProdConfig loads production configuration
func (c *Config) loadProdConfig() {
	c.PublicMode = os.Getenv("TUNN_PUBLIC_MODE") == "true"
	// Production domain
	c.Domain = getEnvOrDefault("TUNN_DOMAIN", "tunn.to")

	// Production certificates (Fly.io paths)
	c.CertFile = getEnvOrDefault("TUNN_CERT_FILE", "/app/certs/fullchain.pem")
	c.KeyFile = getEnvOrDefault("TUNN_KEY_FILE", "/app/certs/privkey.pem")

	// HTTP listener address (TUNN_ADDR sets both, or use TUNN_HTTP2_ADDR/TUNN_HTTP3_ADDR for separate control)
	prodDefaultAddr := getEnvOrDefault("TUNN_ADDR", ":8443")
	c.HTTP2Addr = getEnvOrDefault("TUNN_HTTP2_ADDR", prodDefaultAddr)
	c.HTTP3Addr = getEnvOrDefault("TUNN_HTTP3_ADDR", prodDefaultAddr)

	// Internal gRPC
	c.InternalGRPCPort = getEnvOrDefault("TUNN_INTERNAL_GRPC_PORT", ":50051")
	c.NodeAddresses = getEnvOrDefault("TUNN_NODE_ADDRESSES", "")
	c.NodeSecret = getEnvOrDefault("TUNN_NODE_SECRET", "") // Must be set in prod for multi-node
	c.PublicAddr = getEnvOrDefault("TUNN_PUBLIC_ADDR", "tunn.to:443")
	c.FlyAppName = getEnvOrDefault("FLY_APP_NAME", "")     // Fly.io sets this automatically
	c.InternalCACert = getEnvOrDefault("TUNN_CA_CERT", "") // Custom CA for internal TLS (self-hosters)

	// No mock OIDC in production
	c.MockOIDCAddr = ""
	c.MockOIDCIssuer = ""

	// Server address for clients
	c.ServerAddr = getEnvOrDefault("TUNN_SERVER_ADDR", "tunn.to:443")

	// Tunnel creation key (free tier)
	c.WellKnownKey = getEnvOrDefault("TUNN_WELL_KNOWN_KEY", "tunn-free-v1-2025")

	// GitHub OAuth (required in prod for tunn.to)
	c.GitHubClientID = getEnvOrDefault("TUNN_GITHUB_CLIENT_ID", "")
	c.GitHubClientSecret = getEnvOrDefault("TUNN_GITHUB_CLIENT_SECRET", "")
	c.JWTSecret = getEnvOrDefault("TUNN_JWT_SECRET", "") // Must be set in prod

	// Client secret (self-hosters only - tunn.to leaves this empty)
	c.ClientSecret = getEnvOrDefault("TUNN_CLIENT_SECRET", "")
	c.UsersFile = getEnvOrDefault("TUNN_USERS_FILE", "")

	// SMTP (for magic link auth)
	c.SMTPHost = getEnvOrDefault("TUNN_SMTP_HOST", "")
	c.SMTPPort = getEnvOrDefault("TUNN_SMTP_PORT", "587")
	c.SMTPUser = getEnvOrDefault("TUNN_SMTP_USER", "")
	c.SMTPPassword = getEnvOrDefault("TUNN_SMTP_PASSWORD", "")
	c.SMTPFrom = getEnvOrDefault("TUNN_SMTP_FROM", "")

	// Stripe (for billing)
	c.StripeSecretKey = getEnvOrDefault("TUNN_STRIPE_SECRET_KEY", "")
	c.StripeWebhookSecret = getEnvOrDefault("TUNN_STRIPE_WEBHOOK_SECRET", "")
	c.StripeCheckoutURLMonthly = getEnvOrDefault("TUNN_STRIPE_CHECKOUT_URL_MONTHLY", "")
	c.StripeCheckoutURLYearly = getEnvOrDefault("TUNN_STRIPE_CHECKOUT_URL_YEARLY", "")
	c.StripePortalURL = getEnvOrDefault("TUNN_STRIPE_PORTAL_URL", "")

	// Verify TLS in production
	c.Insecure = false

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
//   - TUNN_LOGIN_NODE=true env var (self-host)
//   - FLY_PROCESS_GROUP=login (Fly.io automatic)
func IsLoginNode() bool {
	if os.Getenv("TUNN_LOGIN_NODE") == "true" {
		return true
	}
	if os.Getenv("FLY_PROCESS_GROUP") == "login" {
		return true
	}
	return false
}

// getEnvironment determines the current environment
func getEnvironment() Environment {
	env := os.Getenv("TUNN_ENV")
	switch env {
	case "dev", "development":
		return EnvDev
	case "", "prod", "production":
		return EnvProd
	default:
		return Environment(env)
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
