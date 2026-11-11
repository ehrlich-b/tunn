package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joho/godotenv"
)

func TestBillingReadyFixtures(t *testing.T) {
	for _, tc := range []struct {
		file, mode  string
		invalid     bool
		diagnostics []string
	}{
		{"default", "checkout closed", false, []string{"TUNN_BILLING_ENABLED: missing", "TUNN_STRIPE_SECRET_KEY: missing", "TUNN_STRIPE_PRO_PRICE_IDS: missing"}},
		{"closed", "checkout closed", false, nil},
		{"manual", "checkout open with manual activation", false, []string{"TUNN_STRIPE_SECRET_KEY: missing", "TUNN_STRIPE_PRO_PRICE_IDS: missing"}},
		{"automatic", "checkout open with automatic activation", false, nil},
		{"key-only", "checkout open with manual activation", false, []string{"TUNN_STRIPE_PRO_PRICE_IDS: missing"}},
		{"prices-only", "checkout open with manual activation", false, []string{"TUNN_STRIPE_SECRET_KEY: missing"}},
		{"http-url", "checkout closed", true, []string{"TUNN_STRIPE_CHECKOUT_URL_MONTHLY: malformed"}},
		{"wrong-origin", "checkout closed", true, []string{"TUNN_STRIPE_CHECKOUT_URL_MONTHLY: malformed"}},
		{"bad-price", "checkout open with manual activation", true, []string{"TUNN_STRIPE_PRO_PRICE_IDS: malformed"}},
		{"prefix-only-price", "checkout open with manual activation", true, []string{"TUNN_STRIPE_PRO_PRICE_IDS: malformed"}},
		{"punctuation-price", "checkout open with manual activation", true, []string{"TUNN_STRIPE_PRO_PRICE_IDS: malformed"}},
		{"underscore-price", "checkout open with manual activation", true, []string{"TUNN_STRIPE_PRO_PRICE_IDS: malformed"}},
		{"unicode-price", "checkout open with manual activation", true, []string{"TUNN_STRIPE_PRO_PRICE_IDS: malformed"}},
		{"space-price", "checkout open with manual activation", true, []string{"TUNN_STRIPE_PRO_PRICE_IDS: malformed"}},
		{"mixed-prices", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_PRO_PRICE_IDS: malformed"}},
		{"long-price", "checkout open with manual activation", true, []string{"TUNN_STRIPE_PRO_PRICE_IDS: malformed"}},
		{"no-webhook", "checkout closed", true, []string{"TUNN_STRIPE_WEBHOOK_SECRET: required"}},
		{"no-url", "checkout closed", true, []string{"TUNN_STRIPE_CHECKOUT_URL_MONTHLY: at least one", "TUNN_STRIPE_CHECKOUT_URL_YEARLY: at least one"}},
		{"bad-boolean", "checkout closed", true, []string{"TUNN_BILLING_ENABLED: malformed"}},
		{"punctuation-key", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_SECRET_KEY: malformed"}},
		{"punctuation-webhook", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_WEBHOOK_SECRET: malformed"}},
		{"prefix-only-key", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_SECRET_KEY: malformed"}},
		{"empty-key-token", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_SECRET_KEY: malformed"}},
		{"prefix-only-webhook", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_WEBHOOK_SECRET: malformed"}},
		{"underscore-key", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_SECRET_KEY: malformed"}},
		{"underscore-webhook", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_WEBHOOK_SECRET: malformed"}},
		{"unicode-key", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_SECRET_KEY: malformed"}},
		{"unicode-webhook", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_WEBHOOK_SECRET: malformed"}},
		{"space-key", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_SECRET_KEY: malformed"}},
		{"space-webhook", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_WEBHOOK_SECRET: malformed"}},
		{"wrong-key-mode", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_SECRET_KEY: malformed"}},
		{"automatic-live", "checkout open with automatic activation", false, nil},
		{"bad-key", "checkout open with automatic activation", true, []string{"TUNN_STRIPE_SECRET_KEY: malformed"}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join("scripts/testdata/billing-ready", tc.file+".vars")
			values, err := godotenv.Read(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, source := range []string{"file", "environment"} {
				t.Run(source, func(t *testing.T) {
					args := []string{"scripts/check-billing-ready.sh"}
					env := opsScriptEnvironment()
					if source == "file" {
						args = append(args, path)
						// A file must not inherit even contradictory ambient config.
						env = append(env, "TUNN_BILLING_ENABLED=invalid", "TUNN_STRIPE_SECRET_KEY=ambient-secret-never-print")
					} else {
						for name, value := range values {
							env = append(env, name+"="+value)
						}
					}
					cmd := exec.Command("bash", args...)
					cmd.Env = env
					output, runErr := cmd.CombinedOutput()
					if (runErr != nil) != tc.invalid {
						t.Fatalf("wrong exit status: %v\n%s", runErr, output)
					}
					line, _, _ := strings.Cut(string(output), "\n")
					if line != tc.mode {
						t.Fatalf("mode = %q, want %q", line, tc.mode)
					}
					for _, diagnostic := range tc.diagnostics {
						if !strings.Contains(string(output), diagnostic) {
							t.Fatalf("missing diagnostic %q", diagnostic)
						}
					}
					for name, value := range values {
						if value != "" && name != "TUNN_BILLING_ENABLED" && strings.Contains(string(output), value) {
							t.Fatalf("output disclosed %s", name)
						}
					}
					if strings.Contains(string(output), "ambient-secret-never-print") {
						t.Fatal("ambient secret disclosed")
					}
				})
			}
		})
	}
	checklist, err := os.ReadFile("docs/paid-operator-checklist.md")
	if err != nil || !strings.Contains(string(checklist), "scripts/check-billing-ready.sh") {
		t.Fatal("operator checklist must name billing check")
	}
}

func TestBillingReadyRejectsUnsafeEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsafe.env")
	marker := filepath.Join(t.TempDir(), "executed")
	// This file must be treated as data, never sourced by a shell.
	data := "TUNN_STRIPE_SECRET_KEY=$(touch " + marker + ")\nTUNN_STRIPE_WEBHOOK_SECRET='whsec_do_not_disclose'\ninvalid fixture secret text\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "scripts/check-billing-ready.sh", path)
	cmd.Env = opsScriptEnvironment()
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.HasPrefix(string(output), "checkout closed\n") {
		t.Fatal("unsafe assignment accepted")
	}
	for _, secret := range []string{marker, "whsec_do_not_disclose", "invalid fixture secret text"} {
		if strings.Contains(string(output), secret) {
			t.Fatal("unsafe input disclosed")
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("env file executed a command")
	}
	cmd = exec.Command("bash", "scripts/check-billing-ready.sh", filepath.Join(t.TempDir(), "missing.env"))
	output, err = cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "env file: unreadable") {
		t.Fatal("missing env file accepted")
	}
}
