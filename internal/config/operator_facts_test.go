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
