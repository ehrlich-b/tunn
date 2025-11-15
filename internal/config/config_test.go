package config

import (
	"os"
	"testing"
)

func TestLoadConfigDev(t *testing.T) {
	// Set dev environment
	os.Setenv("ENV", "dev")
	defer os.Unsetenv("ENV")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Environment != EnvDev {
		t.Errorf("Expected dev environment, got %s", cfg.Environment)
	}

	if !cfg.IsDev() {
		t.Error("Expected IsDev() to return true")
	}

	if cfg.IsProd() {
		t.Error("Expected IsProd() to return false")
	}

	// Check dev-specific values
	if cfg.Domain != "tunn.local.127.0.0.1.nip.io" {
		t.Errorf("Expected nip.io domain, got %s", cfg.Domain)
	}

	if cfg.MockOIDCAddr != ":9000" {
		t.Errorf("Expected mock OIDC addr :9000, got %s", cfg.MockOIDCAddr)
	}

	if !cfg.SkipVerify {
		t.Error("Expected SkipVerify to be true in dev")
	}
}

func TestLoadConfigProd(t *testing.T) {
	// Set prod environment
	os.Setenv("ENV", "prod")
	defer os.Unsetenv("ENV")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Environment != EnvProd {
		t.Errorf("Expected prod environment, got %s", cfg.Environment)
	}

	if cfg.IsDev() {
		t.Error("Expected IsDev() to return false")
	}

	if !cfg.IsProd() {
		t.Error("Expected IsProd() to return true")
	}

	// Check prod-specific values
	if cfg.Domain != "tunn.to" {
		t.Errorf("Expected tunn.to domain, got %s", cfg.Domain)
	}

	if cfg.MockOIDCAddr != "" {
		t.Errorf("Expected empty mock OIDC addr, got %s", cfg.MockOIDCAddr)
	}

	if cfg.SkipVerify {
		t.Error("Expected SkipVerify to be false in prod")
	}
}

func TestLoadConfigDefault(t *testing.T) {
	// Unset ENV to test default behavior
	os.Unsetenv("ENV")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Should default to dev
	if cfg.Environment != EnvDev {
		t.Errorf("Expected default to dev environment, got %s", cfg.Environment)
	}
}

func TestLoadConfigEnvOverride(t *testing.T) {
	// Set environment variables to override defaults
	os.Setenv("ENV", "dev")
	os.Setenv("DOMAIN", "custom.example.com")
	os.Setenv("CERT_FILE", "/custom/cert.pem")
	defer func() {
		os.Unsetenv("ENV")
		os.Unsetenv("DOMAIN")
		os.Unsetenv("CERT_FILE")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Domain != "custom.example.com" {
		t.Errorf("Expected custom domain, got %s", cfg.Domain)
	}

	if cfg.CertFile != "/custom/cert.pem" {
		t.Errorf("Expected custom cert file, got %s", cfg.CertFile)
	}
}

func TestGetEnvOrDefault(t *testing.T) {
	// Test with set value
	os.Setenv("TEST_KEY", "test_value")
	defer os.Unsetenv("TEST_KEY")

	value := getEnvOrDefault("TEST_KEY", "default")
	if value != "test_value" {
		t.Errorf("Expected test_value, got %s", value)
	}

	// Test with unset value
	value = getEnvOrDefault("NONEXISTENT_KEY", "default")
	if value != "default" {
		t.Errorf("Expected default, got %s", value)
	}
}
