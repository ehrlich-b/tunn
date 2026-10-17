package config

import (
	"strings"
	"testing"
)

func TestHTTP3EnvironmentSwitch(t *testing.T) {
	opsCleanEnvironment(t)
	for _, env := range []string{"", "prod", "production", "dev", "development"} {
		for _, setting := range []string{"", "on", "off"} {
			t.Run(env+"/"+setting, func(t *testing.T) {
				t.Setenv("TUNN_ENV", env)
				t.Setenv("TUNN_HTTP3", setting)
				cfg, err := LoadConfig()
				if err != nil {
					t.Fatal(err)
				}
				want := setting == "on" || setting == "" && (env == "dev" || env == "development")
				if cfg.HTTP3Enabled() != want {
					t.Fatalf("HTTP3Enabled=%v want %v", cfg.HTTP3Enabled(), want)
				}
			})
		}
	}
	for _, setting := range []string{"true", "false", "ON", " off", "invalid"} {
		t.Setenv("TUNN_HTTP3", setting)
		if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "TUNN_HTTP3") {
			t.Fatalf("invalid setting %q: %v", setting, err)
		}
	}
}
