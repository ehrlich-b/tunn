package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/hostmode"
)

// Source-built CLI defaults through the exact configuration loader used by
// serve, connect, login and management commands. Executing the built CLI is
// an additional ordinary-host acceptance gate.
func TestCandidateCLIHTTPSDefaultsAndExplicitIsolation(t *testing.T) {
	for _, key := range []string{"TUNN_ENV", "TUNN_SERVER_ADDR", "TUNN_DOMAIN", "TUNN_JWT_SECRET", "TUNN_NODE_SECRET", "TUNN_CLIENT_SECRET", "TUNN_GITHUB_CLIENT_ID", "TUNN_GITHUB_CLIENT_SECRET", "TUNN_METERING_MODE", "TUNN_HTTP2_ADDR", "TUNN_HTTP3_ADDR", "TUNN_PORT", "TUNN_PUBLIC_ADDR"} {
		t.Setenv(key, "")
	}
	root := t.TempDir()
	configDir := filepath.Join(root, "config with spaces")
	if e := os.MkdirAll(configDir, 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("TUNN_CONFIG_DIR", configDir)
	cfg, e := config.LoadConfig()
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Environment != config.EnvProd || cfg.ServerAddr != "tunn.to:443" || cfg.Insecure {
		t.Fatalf("source CLI HTTPS defaults: %+v", cfg)
	}
	for _, addr := range []string{"relay.invalid:443", "127.0.0.1:10443"} {
		t.Setenv("TUNN_SERVER_ADDR", addr)
		cfg, e = config.LoadConfig()
		if e != nil || cfg.ServerAddr != addr || cfg.Insecure {
			t.Fatalf("explicit isolated relay: %+v %v", cfg, e)
		}
	}
	entries, e := os.ReadDir(configDir)
	if e != nil || len(entries) != 0 {
		t.Fatalf("configuration loader read/wrote credential fixture: %v %v", entries, e)
	}
}

// Neither parsing nor the offline installation preparation activates a service.
func TestCandidateInstallationConfigPaths(t *testing.T) {
	root := t.TempDir()
	original := []byte("# Preserve this owner comment and all original bytes.\nversion: 1\nmachine: candidate-host\nserver: relay.invalid:443\ndomain: candidate.invalid\ntunnels:\n  - name: useful-task\n    kind: http\n    target: http://127.0.0.1:18080\n    allow: [owner@example.com]\n")
	for _, name := range []string{"first install with spaces", "second install with spaces"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, name)
			if e := os.MkdirAll(dir, 0700); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, "host config.yaml")
			if e := os.WriteFile(path, original, 0600); e != nil {
				t.Fatal(e)
			}
			cfg, e := hostmode.Load(path)
			if e != nil {
				t.Fatal(e)
			}
			if cfg.Server != "relay.invalid:443" || cfg.Insecure || cfg.TokenFile != "" || cfg.CredentialsDir != "" {
				t.Fatalf("optional config/defaults: %+v", cfg)
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(after, original) {
				t.Fatalf("config bytes changed: %v", e)
			}
			opts, e := parseServeFlags([]string{"http://127.0.0.1:18080", "--name", "useful-task", "--allow", "owner@example.com", "--secret", "synthetic-candidate-secret", "--tunnel-key", "synthetic-key"})
			if e != nil || opts.target != "http://127.0.0.1:18080" || opts.tunnelID != "useful-task" || opts.clientSecret != "synthetic-candidate-secret" {
				t.Fatalf("documented useful command: %+v %v", opts, e)
			}
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) != 1 {
				t.Fatalf("parsing created optional credentials/config: %v %v", entries, e)
			}
		})
	}
}
