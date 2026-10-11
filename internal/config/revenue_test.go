package config

import "testing"

func TestRevenueBillingConfigDefaultsOverridesAndInvalidValues(t *testing.T) {
	opsCleanEnvironment(t)
	for _, env := range []string{"dev", "prod"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("TUNN_ENV", env)
			cfg, err := LoadConfig()
			if err != nil || cfg.BillingEnabled || cfg.ProMonthlyUSD != 6 || cfg.ProYearlyUSD != 60 {
				t.Fatal(cfg, err)
			}
			t.Setenv("TUNN_BILLING_ENABLED", "true")
			t.Setenv("TUNN_PRO_MONTHLY_USD", "8")
			t.Setenv("TUNN_PRO_YEARLY_USD", "80")
			cfg, err = LoadConfig()
			if err != nil || !cfg.BillingEnabled || cfg.ProMonthlyUSD != 8 || cfg.ProYearlyUSD != 80 {
				t.Fatal(cfg, err)
			}
		})
	}
	for _, key := range []string{"TUNN_PRO_MONTHLY_USD", "TUNN_PRO_YEARLY_USD"} {
		for _, bad := range []string{"0", "-1", "6.00", "invalid", "10001"} {
			t.Run(key+bad, func(t *testing.T) {
				t.Setenv(key, bad)
				if _, err := LoadConfig(); err == nil {
					t.Fatal("invalid price accepted")
				}
			})
		}
	}
	t.Setenv("TUNN_BILLING_ENABLED", "yes")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("ambiguous billing enable accepted")
	}
}
