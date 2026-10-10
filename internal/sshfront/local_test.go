package sshfront

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestStdioServicePlansAndPumpLifecycle(t *testing.T) {
	manifest := `version: 1
machine: workstation
tunnels:
  - name: tools
    kind: mcp
    command: [node, server.js]
    tools: [read_file]
`
	for _, platform := range []string{"linux", "darwin", "windows"} {
		var out bytes.Buffer
		if err := ServicePlan([]string{"install", "--os", platform}, strings.NewReader(manifest), "tunn.test", &out); err != nil {
			t.Fatal(err)
		}
		s := out.String()
		if !strings.Contains(s, "stdio") || !strings.Contains(s, "read_file") || !strings.Contains(s, "server.js") {
			t.Fatalf("stdio service=%s", s)
		}
		if platform != "windows" {
			cmd := exec.Command("sh", "-n")
			cmd.Stdin = strings.NewReader(s)
			if data, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("invalid script: %s %v", data, err)
			}
		}
	}
	path := filepath.Join(t.TempDir(), "response")
	local := []string{"sh", "-c", `read -r request; [ "$request" = ping ]; printf '%s\n' pong; read -r end`}
	peer := []string{"sh", "-c", `printf '%s\n' ping; read -r response; [ "$response" = pong ]; printf '%s' "$response" > ` + shellQuote(path)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", posixPump(local, peer))
	data, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("pump did not terminate its child: %s %v", data, err)
	}
	if err == nil {
		t.Fatal("persistent pump did not signal restart after peer exit")
	}
	response, err := os.ReadFile(path)
	if err != nil || string(response) != "pong" {
		t.Fatalf("bidirectional pump=%s %v", response, err)
	}
}
