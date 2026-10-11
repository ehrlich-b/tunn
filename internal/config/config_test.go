package config

import (
	"strings"
	"testing"
)

func TestMeteringOwnerBudgetConfiguration(t *testing.T) {
	for _, env := range []string{"dev", "prod"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("TUNN_ENV", env)
			t.Setenv("TUNN_OWNER_MONTHLY_REQUESTS", "1000")
			t.Setenv("TUNN_OWNER_MONTHLY_BYTES", "1000000")
			cfg, err := LoadConfig()
			if err != nil || cfg.OwnerMonthlyRequests != 1000 || cfg.OwnerMonthlyBytes != 1000000 {
				t.Fatalf("config=%v %v", cfg, err)
			}
			for _, key := range []string{"TUNN_OWNER_MONTHLY_REQUESTS", "TUNN_OWNER_MONTHLY_BYTES"} {
				for _, value := range []string{"-1", "bad", "9223372036854775808"} {
					t.Setenv(key, value)
					if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), key) {
						t.Fatalf("accepted %s=%s: %v", key, value, err)
					}
				}
				t.Setenv(key, "0")
			}
		})
	}
}

func TestLoadConfigDev(t *testing.T) {
	// Set dev environment
	t.Setenv("TUNN_ENV", "dev")

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

	if !cfg.Insecure {
		t.Error("Expected Insecure to be true in dev")
	}
}

func TestLoadConfigProd(t *testing.T) {
	// Set prod environment
	t.Setenv("TUNN_ENV", "prod")

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

	if cfg.Insecure {
		t.Error("Expected Insecure to be false in prod")
	}
}

func TestLoadConfigDefault(t *testing.T) {
	// Unset TUNN_ENV to test default behavior
	t.Setenv("TUNN_ENV", "")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Environment != EnvProd || cfg.Insecure || cfg.MockOIDCAddr != "" || cfg.JWTSecret != "" || cfg.NodeSecret != "" {
		t.Errorf("Default must verify TLS and omit development services/secrets: %+v", cfg)
	}
}

func TestLoadConfigRejectsUnknownEnvironment(t *testing.T) {
	t.Setenv("TUNN_ENV", "prd")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("unknown environment must not enable dev mode")
	}
}

func TestLoadConfigEnvOverride(t *testing.T) {
	// Set environment variables to override defaults
	t.Setenv("TUNN_ENV", "dev")
	t.Setenv("TUNN_DOMAIN", "custom.example.com")
	t.Setenv("TUNN_CERT_FILE", "/custom/cert.pem")

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
	t.Setenv("TEST_KEY", "test_value")

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
