package config

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestBuyerTrustPageDeployFacts(t *testing.T) {
	opsCleanEnvironment(t)
	for _, value := range []string{"", "Example & <operator>"} {
		t.Setenv("TUNN_OPERATING_NAME", value)
		t.Setenv("TUNN_MERCHANT_DISPLAY_NAME", value)
		t.Setenv("TUNN_SUPPORT_WINDOW", value)
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.OperatingName != value || cfg.MerchantDisplayName != value || cfg.SupportWindow != value {
			t.Fatal("deploy facts not preserved")
		}
	}
}

func TestMCPVerifiedDeployFact(t *testing.T) {
	opsCleanEnvironment(t)
	for _, env := range []string{"dev", "prod"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("TUNN_ENV", env)
			for _, value := range []string{"", " \t\n", "Claude.ai web 2026-11-12; Claude iOS 2026-11-12", "Example & <client>"} {
				t.Setenv("TUNN_MCP_VERIFIED", value)
				cfg, err := LoadConfig()
				if err != nil {
					t.Fatal(err)
				}
				if cfg.MCPVerified != value || MCPVerifiedFromEnv() != value {
					t.Fatalf("deploy fact: got %q want %q", cfg.MCPVerified, value)
				}
			}
		})
	}
}

// The operator report must agree with the renderer under both byte and UTF-8 locales.
func TestMCPVerifiedOperatorWhitespace(t *testing.T) {
	whitespace := " \t\n\v\f\r\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
	for _, locale := range []string{"C", "C.UTF-8"} {
		for _, value := range []string{"", whitespace, "\u2003", "\u2003Claude.ai web 2026-11-12\u00a0", "\u200b", "\u001c"} {
			cmd := exec.Command("bash", "../../scripts/check-operator-facts.sh")
			cmd.Env = append(os.Environ(), "LC_ALL="+locale, "TUNN_MCP_VERIFIED="+value)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s %q: %v: %s", locale, value, err, output)
			}
			expected := "TUNN_MCP_VERIFIED: unset or blank; Experimental statement will render"
			if strings.TrimSpace(value) != "" {
				expected = "TUNN_MCP_VERIFIED: supplied; Bryan must confirm clients and dates against end-to-end results"
			}
			if !strings.Contains(string(output), expected) {
				t.Errorf("%s %q: expected %q, got %s", locale, value, expected, output)
			}
		}
	}
}
