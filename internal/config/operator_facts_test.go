package config

import "testing"

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
				if cfg.MCPVerified != value {
					t.Fatalf("deploy fact: got %q want %q", cfg.MCPVerified, value)
				}
			}
		})
	}
}
