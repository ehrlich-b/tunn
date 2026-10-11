package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func opsCleanEnvironment(t *testing.T) {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(key, "TUNN_") || strings.HasPrefix(key, "FLY_") {
			t.Setenv(key, "")
		}
	}
}

func TestOpsEnvironmentAliasesAndDefaults(t *testing.T) {
	opsCleanEnvironment(t)
	for _, env := range []string{"", "dev", "development", "prod", "production"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("TUNN_ENV", env)
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			prod := env == "prod" || env == "production"
			if cfg.IsProd() != prod || cfg.IsDev() == prod || cfg.Insecure == prod {
				t.Fatalf("wrong environment defaults: %+v", cfg)
			}
			if prod && (cfg.DBPath != "/data/tunn.db" || cfg.JWTSecret != "" || cfg.NodeSecret != "" || cfg.LoginNode || cfg.MockOIDCAddr != "") {
				t.Fatal("production inherited development settings")
			}
			if !prod && (!cfg.LoginNode || cfg.JWTSecret == "" || cfg.NodeSecret == "") {
				t.Fatal("development defaults missing")
			}
		})
	}
}

func TestOpsEnvironmentAndTypedSettingsRejectInvalidValues(t *testing.T) {
	opsCleanEnvironment(t)
	cases := map[string][]string{
		"TUNN_ENV":       {"prd", "Production", " prod", "test"},
		"TUNN_HOST_MODE": {"yes", "TRUE", "1"}, "TUNN_LOGIN_NODE": {"yes", "TRUE", "1"},
		"TUNN_PUBLIC_MODE": {"yes", "FALSE", "0"}, "TUNN_CUSTOM_DOMAINS": {"yes", "enabled", "1"},
		"TUNN_DOMAIN":     {"https://example.com", "bad host", "example.com:443", "-bad.example"},
		"TUNN_ADDR":       {"8443", ":-1", ":65536", " host:443", ":https"},
		"TUNN_HTTP2_ADDR": {"invalid", ":0"}, "TUNN_HTTP3_ADDR": {"invalid", ":65536"},
		"TUNN_INTERNAL_GRPC_PORT": {"50051", ":0"}, "TUNN_SSH_ADDR": {"22", ":0"},
		"TUNN_HTTP01_ADDR": {"80", ":0"}, "TUNN_MOCK_OIDC_ADDR": {"9000", ":0"},
		"TUNN_PUBLIC_ADDR":    {":443", "https://example.com:443", "example.com"},
		"TUNN_SERVER_ADDR":    {":443", "https://example.com:443", "example.com"},
		"TUNN_NODE_ADDRESSES": {"node:50051,broken", ",node:50051", "node:0"},
		"TUNN_SMTP_PORT":      {"smtp", "0", "65536"}, "TUNN_SMTP_HOST": {"smtp://example.com", "bad host"},
		"TUNN_SMTP_FROM":                   {"not-an-email", "x@example.com\r\nBcc: x@example.net"},
		"TUNN_ACME_EMAIL":                  {"not-an-email"},
		"TUNN_MOCK_OIDC_ISSUER":            {"ftp://example.com", "http://", "http://user:secret@example.com"},
		"TUNN_ACME_DIRECTORY":              {"relative", "https://user:secret@example.com"},
		"TUNN_STRIPE_CHECKOUT_URL_MONTHLY": {"javascript:alert(1)", "http://"},
		"TUNN_STRIPE_CHECKOUT_URL_YEARLY":  {"relative"}, "TUNN_STRIPE_PORTAL_URL": {"relative"},
		"TUNN_DOMAIN_KEY_SECRET": {"not-base64", "c2hvcnQ="},
		"TUNN_CERT_FILE":         {"cert\n.pem"}, "TUNN_KEY_FILE": {"key\n.pem"},
		"TUNN_DB_PATH": {"db\n"}, "TUNN_USERS_FILE": {"users\r.yaml"},
		"TUNN_CA_CERT": {"ca\n.pem"}, "TUNN_SSH_HOST_KEY_FILE": {"key\n"},
	}
	for key, values := range cases {
		for _, value := range values {
			t.Run(key+"/"+value, func(t *testing.T) {
				t.Setenv(key, value)
				_, err := LoadConfig()
				if err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("accepted invalid %s or returned unclear error: %v", key, err)
				}
				if strings.Contains(err.Error(), "user:secret") {
					t.Fatal("error exposed credential")
				}
			})
		}
	}
}

func TestOpsEveryServerEnvironmentOverride(t *testing.T) {
	opsCleanEnvironment(t)
	overrides := map[string]struct{ field, value string }{
		"TUNN_DOMAIN": {"Domain", "relay.example.com"}, "TUNN_CERT_FILE": {"CertFile", "/fixture/cert.pem"},
		"TUNN_KEY_FILE": {"KeyFile", "/fixture/key.pem"}, "TUNN_HTTP2_ADDR": {"HTTP2Addr", "127.0.0.1:8444"},
		"TUNN_HTTP3_ADDR": {"HTTP3Addr", "fly-global-services:443"}, "TUNN_SSH_HOST_KEY_FILE": {"SSHHostKeyFile", "/fixture/ssh.key"},
		"TUNN_SSH_ADDR": {"SSHAddr", "[::1]:2222"}, "TUNN_INTERNAL_GRPC_PORT": {"InternalGRPCPort", ":15051"},
		"TUNN_NODE_ADDRESSES": {"NodeAddresses", "127.0.0.2:50051,[::1]:50051"}, "TUNN_NODE_SECRET": {"NodeSecret", "fixture-node-secret"},
		"TUNN_PUBLIC_ADDR": {"PublicAddr", "relay.example.com:443"}, "TUNN_CA_CERT": {"InternalCACert", "/fixture/ca.pem"},
		"TUNN_MOCK_OIDC_ADDR": {"MockOIDCAddr", ":19000"}, "TUNN_MOCK_OIDC_ISSUER": {"MockOIDCIssuer", "http://localhost:19000"},
		"TUNN_WELL_KNOWN_KEY": {"WellKnownKey", "fixture-creation-key"}, "TUNN_GITHUB_CLIENT_ID": {"GitHubClientID", "fixture-id"},
		"TUNN_GITHUB_CLIENT_SECRET": {"GitHubClientSecret", "fixture-github-secret"}, "TUNN_JWT_SECRET": {"JWTSecret", "fixture-jwt-secret"},
		"TUNN_CLIENT_SECRET": {"ClientSecret", "fixture-client-secret"}, "TUNN_USERS_FILE": {"UsersFile", "/fixture/users.yaml"},
		"TUNN_SMTP_HOST": {"SMTPHost", "smtp.example.com"}, "TUNN_SMTP_PORT": {"SMTPPort", "2525"},
		"TUNN_SMTP_USER": {"SMTPUser", "fixture-user"}, "TUNN_SMTP_PASSWORD": {"SMTPPassword", "fixture-smtp-secret"},
		"TUNN_SMTP_FROM": {"SMTPFrom", "Tunn <noreply@example.com>"}, "TUNN_STRIPE_SECRET_KEY": {"StripeSecretKey", "fixture-stripe-key"},
		"TUNN_STRIPE_WEBHOOK_SECRET":       {"StripeWebhookSecret", "fixture-webhook-secret"},
		"TUNN_STRIPE_CHECKOUT_URL_MONTHLY": {"StripeCheckoutURLMonthly", "https://buy.stripe.com/month"},
		"TUNN_STRIPE_CHECKOUT_URL_YEARLY":  {"StripeCheckoutURLYearly", "https://buy.stripe.com/year"},
		"TUNN_STRIPE_PORTAL_URL":           {"StripePortalURL", "https://billing.stripe.com/portal"},
		"TUNN_SERVER_ADDR":                 {"ServerAddr", "relay.example.com:443"}, "TUNN_DB_PATH": {"DBPath", "/fixture/tunn.db"},
		"TUNN_HTTP01_ADDR": {"HTTP01Addr", ":8080"}, "TUNN_ACME_DIRECTORY": {"ACMEDirectory", "https://acme.example.com/directory"},
		"TUNN_ACME_EMAIL": {"ACMEEmail", "ops@example.com"}, "TUNN_DOMAIN_KEY_SECRET": {"DomainKeySecret", strings.Repeat("A", 43) + "="},
	}
	for _, env := range []string{"dev", "prod"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("TUNN_ENV", env)
			for key, test := range overrides {
				t.Setenv(key, test.value)
			}
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			fields := reflect.ValueOf(cfg).Elem()
			for key, test := range overrides {
				want := test.value
				if env == "prod" && strings.HasPrefix(key, "TUNN_MOCK_OIDC") {
					want = ""
				}
				if got := fields.FieldByName(test.field).String(); got != want {
					t.Errorf("%s override: got %q want %q", key, got, want)
				}
			}
		})
	}
}

func TestOpsListenerPrecedenceAndBooleanOverrides(t *testing.T) {
	opsCleanEnvironment(t)
	t.Setenv("TUNN_ADDR", ":9443")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP2Addr != ":9443" || cfg.HTTP3Addr != ":9443" {
		t.Fatal("shared address not used")
	}
	t.Setenv("TUNN_HTTP2_ADDR", ":9444")
	t.Setenv("TUNN_HTTP3_ADDR", ":9445")
	t.Setenv("TUNN_MOCK_OIDC_ADDR", "")
	for _, value := range []string{"true", "false"} {
		for _, key := range []string{"TUNN_HOST_MODE", "TUNN_PUBLIC_MODE", "TUNN_CUSTOM_DOMAINS", "TUNN_LOGIN_NODE"} {
			t.Setenv(key, value)
		}
		cfg, err = LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		want := value == "true"
		if cfg.HostModeEnabled != want || cfg.PublicMode != want || cfg.CustomDomainsEnabled != want || cfg.LoginNode != want {
			t.Fatal("boolean override ignored")
		}
		if cfg.HTTP2Addr != ":9444" || cfg.HTTP3Addr != ":9445" || cfg.MockOIDCAddr != "" {
			t.Fatal("listener precedence or explicit OIDC disable ignored")
		}
	}
	t.Setenv("FLY_PROCESS_GROUP", "login")
	cfg, err = LoadConfig()
	if err != nil || !cfg.LoginNode {
		t.Fatal("Fly login group not authoritative")
	}
}

func TestOpsHostStartupRequirements(t *testing.T) {
	opsCleanEnvironment(t)
	t.Setenv("TUNN_ENV", "prod")
	base, err := LoadConfig()
	if err != nil {
		t.Fatal("production clients must load config without host secrets:", err)
	}
	base.LoginNode = true
	base.JWTSecret = "fixture-production-signing-secret"
	path := filepath.Join(t.TempDir(), "fixture.pem")
	if err := os.WriteFile(path, []byte("TLS loading is checked by the host constructor"), 0600); err != nil {
		t.Fatal(err)
	}
	base.CertFile, base.KeyFile = path, path
	if err := base.ValidateHost(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, key string
		change    func(*Config)
	}{
		{"jwt absent", "TUNN_JWT_SECRET", func(c *Config) { c.JWTSecret = "" }},
		{"dev jwt", "TUNN_JWT_SECRET", func(c *Config) { c.JWTSecret = "dev-jwt-secret-do-not-use-in-prod" }},
		{"public production", "TUNN_PUBLIC_MODE", func(c *Config) { c.PublicMode = true }},
		{"standalone without login", "TUNN_LOGIN_NODE", func(c *Config) { c.LoginNode = false }},
		{"cluster secret absent", "TUNN_NODE_SECRET", func(c *Config) { c.NodeAddresses = "node:50051" }},
		{"github id only", "TUNN_GITHUB_CLIENT_SECRET", func(c *Config) { c.GitHubClientID = "fixture" }},
		{"github secret only", "TUNN_GITHUB_CLIENT_ID", func(c *Config) { c.GitHubClientSecret = "fixture-secret" }},
		{"smtp user only", "TUNN_SMTP_PASSWORD", func(c *Config) { c.SMTPUser = "fixture" }},
		{"smtp password only", "TUNN_SMTP_USER", func(c *Config) { c.SMTPPassword = "fixture-secret" }},
		{"smtp without from", "TUNN_SMTP_FROM", func(c *Config) { c.SMTPHost = "smtp.example.com" }},
		{"smtp without host", "TUNN_SMTP_HOST", func(c *Config) { c.SMTPFrom = "test@example.com" }},
		{"ssh address only", "TUNN_SSH_HOST_KEY_FILE", func(c *Config) { c.SSHAddr = ":22" }},
		{"custom domains without key", "TUNN_DOMAIN_KEY_SECRET", func(c *Config) { c.CustomDomainsEnabled = true }},
		{"custom domains without contact", "TUNN_ACME_EMAIL", func(c *Config) { c.CustomDomainsEnabled = true; c.DomainKeySecret = strings.Repeat("A", 43) + "=" }},
		{"host mode on cluster", "TUNN_HOST_MODE", func(c *Config) { c.HostModeEnabled = true; c.FlyAppName = "fixture"; c.NodeSecret = "fixture-secret" }},
		{"bad cli domain", "TUNN_DOMAIN", func(c *Config) { c.Domain = "https://example.com" }},
		{"missing cert", "TUNN_CERT_FILE", func(c *Config) { c.CertFile = path + ".missing" }},
		{"directory key", "TUNN_KEY_FILE", func(c *Config) { c.KeyFile = filepath.Dir(path) }},
		{"missing users", "TUNN_USERS_FILE", func(c *Config) { c.UsersFile = path + ".missing" }},
		{"missing ca", "TUNN_CA_CERT", func(c *Config) { c.InternalCACert = path + ".missing" }},
		{"missing ssh key", "TUNN_SSH_HOST_KEY_FILE", func(c *Config) { c.SSHHostKeyFile = path + ".missing" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg := *base
			test.change(&cfg)
			if err := cfg.ValidateHost(); err == nil || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("unclear startup error: %v", err)
			}
		})
	}
}

func TestOpsOpaqueSettingsRejectBlankAndLineBreakValues(t *testing.T) {
	opsCleanEnvironment(t)
	for _, key := range []string{"TUNN_NODE_SECRET", "TUNN_JWT_SECRET", "TUNN_WELL_KNOWN_KEY", "TUNN_GITHUB_CLIENT_ID", "TUNN_GITHUB_CLIENT_SECRET", "TUNN_CLIENT_SECRET", "TUNN_SMTP_USER", "TUNN_SMTP_PASSWORD", "TUNN_STRIPE_SECRET_KEY", "TUNN_STRIPE_WEBHOOK_SECRET"} {
		for _, value := range []string{"  ", "fixture-private-value\n"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				t.Setenv(key, value)
				_, err := LoadConfig()
				if err == nil || !strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "fixture-private-value") {
					t.Fatalf("invalid or secret-bearing error: %v", err)
				}
			})
		}
	}
}
