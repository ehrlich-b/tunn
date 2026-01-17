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
	NodeAddresses    string // Comma-separated list of other node addresses
	NodeSecret       string // Shared secret for node-to-node authentication
	PublicAddr       string

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

	// Client configuration
	ServerAddr string
	SkipVerify bool
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

	// HTTP listener addresses (configurable for integration tests)
	c.HTTP2Addr = getEnvOrDefault("HTTP2_ADDR", ":8443")
	c.HTTP3Addr = getEnvOrDefault("HTTP3_ADDR", ":8443")

	// Internal gRPC
	c.InternalGRPCPort = getEnvOrDefault("INTERNAL_GRPC_PORT", ":50051")
	c.NodeAddresses = getEnvOrDefault("NODE_ADDRESSES", "")
	c.NodeSecret = getEnvOrDefault("NODE_SECRET", "dev-node-secret")
	c.PublicAddr = getEnvOrDefault("PUBLIC_ADDR", "localhost:8443")

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

	// Skip TLS verification in dev
	c.SkipVerify = true
}

// loadProdConfig loads production configuration
func (c *Config) loadProdConfig() {
	// Production domain
	c.Domain = getEnvOrDefault("DOMAIN", "tunn.to")

	// Production certificates (Fly.io paths)
	c.CertFile = getEnvOrDefault("CERT_FILE", "/app/certs/fullchain.pem")
	c.KeyFile = getEnvOrDefault("KEY_FILE", "/app/certs/privkey.pem")

	// HTTP listener addresses (Fly.io routes 443/tcp and 443/udp to these)
	c.HTTP2Addr = getEnvOrDefault("HTTP2_ADDR", ":8443")
	c.HTTP3Addr = getEnvOrDefault("HTTP3_ADDR", ":8443")

	// Internal gRPC
	c.InternalGRPCPort = getEnvOrDefault("INTERNAL_GRPC_PORT", ":50051")
	c.NodeAddresses = getEnvOrDefault("NODE_ADDRESSES", "")
	c.NodeSecret = getEnvOrDefault("NODE_SECRET", "") // Must be set in prod for multi-node
	c.PublicAddr = getEnvOrDefault("PUBLIC_ADDR", "tunn.to:443")

	// No mock OIDC in production
	c.MockOIDCAddr = ""
	c.MockOIDCIssuer = ""

	// Server address for clients
	c.ServerAddr = getEnvOrDefault("SERVER_ADDR", "tunn.to:443")

	// Tunnel creation key (free tier)
	c.WellKnownKey = getEnvOrDefault("WELL_KNOWN_KEY", "tunn-free-v1-2025")

	// GitHub OAuth (required in prod)
	c.GitHubClientID = getEnvOrDefault("GITHUB_CLIENT_ID", "")
	c.GitHubClientSecret = getEnvOrDefault("GITHUB_CLIENT_SECRET", "")
	c.JWTSecret = getEnvOrDefault("JWT_SECRET", "") // Must be set in prod

	// Verify TLS in production
	c.SkipVerify = false
}

// IsDev returns true if running in development environment
func (c *Config) IsDev() bool {
	return c.Environment == EnvDev
}

// IsProd returns true if running in production environment
func (c *Config) IsProd() bool {
	return c.Environment == EnvProd
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
