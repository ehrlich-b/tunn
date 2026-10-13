package config

import "testing"

func TestStatusCollectorConfiguration(t *testing.T) {
	opsCleanEnvironment(t)
	for _, raw := range []string{"", "https://status.example", "http://127.0.0.1:8091"} {
		t.Setenv("TUNN_STATUS_URL", raw)
		cfg, err := LoadConfig()
		if err != nil || cfg.StatusURL != raw {
			t.Fatal(cfg, err)
		}
	}
	for _, raw := range []string{"https://user:pass@status.example", "https://status.example/status", "ftp://status.example", "https://status.example?x=y", "https://status.example#x"} {
		t.Setenv("TUNN_STATUS_URL", raw)
		if _, err := LoadConfig(); err == nil {
			t.Fatal("invalid collector accepted", raw)
		}
	}
}
