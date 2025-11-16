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
	Domain   string
	CertFile string
	KeyFile  string

	// Internal gRPC configuration
	InternalGRPCPort     string
	InternalCACertFile   string
	InternalNodeCertFile string
	InternalNodeKeyFile  string
	NodeAddresses        string // Comma-separated list of other node addresses
	PublicAddr           string

	// Mock OIDC configuration (dev only)
	MockOIDCAddr   string
	MockOIDCIssuer string

	// Tunnel creation authorization
	WellKnownKey string // Free tier key that allows anyone to create tunnels

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

	// Internal gRPC
	c.InternalGRPCPort = getEnvOrDefault("INTERNAL_GRPC_PORT", ":50051")
	c.InternalCACertFile = getEnvOrDefault("INTERNAL_CA_CERT_FILE", "./certs/ca.pem")
	c.InternalNodeCertFile = getEnvOrDefault("INTERNAL_NODE_CERT_FILE", "./certs/cert.pem")
	c.InternalNodeKeyFile = getEnvOrDefault("INTERNAL_NODE_KEY_FILE", "./certs/key.pem")
	c.NodeAddresses = getEnvOrDefault("NODE_ADDRESSES", "localhost:50051")
	c.PublicAddr = getEnvOrDefault("PUBLIC_ADDR", "localhost:8443")

	// Mock OIDC provider runs locally
	c.MockOIDCAddr = getEnvOrDefault("MOCK_OIDC_ADDR", ":9000")
	c.MockOIDCIssuer = getEnvOrDefault("MOCK_OIDC_ISSUER", "http://localhost:9000")

	// Server address for clients
	c.ServerAddr = getEnvOrDefault("SERVER_ADDR", "localhost:8443")

	// Tunnel creation key (free tier)
	c.WellKnownKey = getEnvOrDefault("WELL_KNOWN_KEY", "tunn-free-v1-2025")

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

	// Internal gRPC
	c.InternalGRPCPort = getEnvOrDefault("INTERNAL_GRPC_PORT", ":50051")
	c.InternalCACertFile = getEnvOrDefault("INTERNAL_CA_CERT_FILE", "/app/certs/ca.pem")
	c.InternalNodeCertFile = getEnvOrDefault("INTERNAL_NODE_CERT_FILE", "/app/certs/fullchain.pem")
	c.InternalNodeKeyFile = getEnvOrDefault("INTERNAL_NODE_KEY_FILE", "/app/certs/privkey.pem")
	c.NodeAddresses = getEnvOrDefault("NODE_ADDRESSES", "") // In prod, this should be discovered via DNS
	c.PublicAddr = getEnvOrDefault("PUBLIC_ADDR", "tunn.to:443")

	// No mock OIDC in production
	c.MockOIDCAddr = ""
	c.MockOIDCIssuer = ""

	// Server address for clients
	c.ServerAddr = getEnvOrDefault("SERVER_ADDR", "tunn.to:443")

	// Tunnel creation key (free tier)
	c.WellKnownKey = getEnvOrDefault("WELL_KNOWN_KEY", "tunn-free-v1-2025")

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
