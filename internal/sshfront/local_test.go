package sshfront

import (
	"bytes"
	"strings"
	"testing"
)

func TestServicePlansUseLocalOpenSSH(t *testing.T) {
	manifest := `version: 1
machine: workstation
tunnels:
  - name: demo
    kind: http
    target: 8080
    allow: [owner@example.com]
`
	for _, platform := range []string{"linux", "darwin", "windows"} {
		var out bytes.Buffer
		if err := ServicePlan([]string{"install", "--os", platform, "--config", "-"}, strings.NewReader(manifest), "tunn.test", &out); err != nil {
			t.Fatal(err)
		}
		s := out.String()
		if !strings.Contains(s, "ssh") || !strings.Contains(s, "8080") || !strings.Contains(s, "owner@example.com") || strings.Contains(s, "tunn service run") {
			t.Fatalf("invalid %s service: %s", platform, s)
		}
	}
	var out bytes.Buffer
	if err := ServicePlan([]string{"install", "--dry-run"}, strings.NewReader(manifest), "tunn.test", &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "systemctl --user enable") {
		t.Fatal("dry run contains installation actions")
	}
	if err := ServicePlan([]string{"install", "--config", "/etc/passwd"}, strings.NewReader(manifest), "tunn.test", &out); err == nil {
		t.Fatal("read relay filesystem from a remote command")
	}
	if shellQuote("hello'$(touch x)") != "'hello'\"'\"'$(touch x)'" {
		t.Fatal("unsafe shell quoting")
	}
}
