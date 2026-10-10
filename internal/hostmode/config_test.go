package hostmode

import (
	"strings"
	"testing"
)

const validConfig = `version: 1
machine: gpu-box
health: 127.0.0.1:0
tunnels:
  - name: gpu-http
    kind: http
    target: "8080"
    allow: [owner@example.com, "@example.org"]
  - name: gpu-ssh
    kind: tcp
    target: 127.0.0.1:22
  - name: gpu-socket
    kind: unix
    target: /tmp/gpu.sock
  - name: gpu-mcp
    kind: mcp
    command: [/usr/bin/echo, test]
    tools: [read_file]
`

func TestConfig(t *testing.T) {
	c, err := Parse([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if c.Machine != "gpu-box" || len(c.Tunnels) != 4 || c.Tunnels[0].Allow[1] != "@example.org" {
		t.Fatalf("config = %#v", c)
	}
	for name, content := range map[string]string{
		"unknown":              validConfig + "surprise: true\n",
		"version":              strings.Replace(validConfig, "version: 1", "version: 2", 1),
		"machine":              strings.Replace(validConfig, "gpu-box", "GPU_BOX", 1),
		"remote health":        strings.Replace(validConfig, "127.0.0.1:0", "0.0.0.0:9087", 1),
		"health hostname":      strings.Replace(validConfig, "127.0.0.1:0", "localhost:9087", 1),
		"http public":          strings.Replace(validConfig, "    allow: [owner@example.com, \"@example.org\"]\n", "", 1),
		"duplicate":            strings.Replace(validConfig, "gpu-ssh", "gpu-http", 1),
		"tcp port":             strings.Replace(validConfig, "127.0.0.1:22", "127.0.0.1:0", 1),
		"unknown adapter":      strings.Replace(validConfig, "kind: tcp", "kind: udp", 1),
		"mcp ambiguity":        validConfig + "    target: http://127.0.0.1:3000/mcp\n",
		"second document":      validConfig + "---\nversion: 1\n",
		"credentials":          strings.Replace(validConfig, "\"8080\"", "http://secret:password@localhost:8080", 1),
		"relative token":       validConfig + "token_file: ./token\n",
		"relative credentials": validConfig + "credentials_dir: ./credentials\n",
		"socket mode":          strings.Replace(validConfig, "kind: unix", "kind: unix\n    as: tcp", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(content)); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}
