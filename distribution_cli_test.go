package main

import (
	"encoding/json"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Validate the commands readers copy from the actual pages without logging in,
// downloading an MCP server, publishing an endpoint, or opening any listener.
func TestDistributionCLICommands(t *testing.T) {
	files, err := filepath.Glob("internal/host/templates/*-*.html")
	if err != nil {
		t.Fatal(err)
	}
	// Generated help blocks use class="cli-help": they contain syntax, not runnable examples.
	// Their exact content is checked against the binary by make test-docs.
	files = append(files, "internal/host/templates/docs.html")
	blocks := regexp.MustCompile(`(?s)<pre><code>(.*?)</code></pre>`)
	var checked int
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, block := range blocks.FindAllStringSubmatch(string(data), -1) {
			// Parse shell quoting and continuations without executing examples.
			source := strings.ReplaceAll(html.UnescapeString(block[1]), "\\\n", "")
			for _, line := range strings.Split(source, "\n") {
				if !strings.HasPrefix(strings.TrimSpace(line), "tunn ") {
					continue
				}
				parsed, err := exec.Command("python3", "-c", "import json,shlex,sys; print(json.dumps(shlex.split(sys.argv[1])))", line).Output()
				if err != nil {
					t.Fatalf("%s: invalid shell quoting: %v", file, err)
				}
				var args []string
				if err := json.Unmarshal(parsed, &args); err != nil {
					t.Fatal(err)
				}
				if len(args) < 2 || args[0] != "tunn" {
					continue
				}
				switch args[1] {
				case "login":
					if len(args) != 2 {
						t.Errorf("unexpected login arguments: %s", line)
					}
				case "http", "serve":
					if _, err := parseServeFlags(args[2:]); err != nil {
						t.Errorf("%s: %s: %v", file, line, err)
					}
				case "share", "unshare", "access":
					if _, err := parseSharing(args[1], args[2:]); err != nil {
						t.Errorf("%s: %s: %v", file, line, err)
					}
				case "usage", "grant":
					if _, err := parseMeteringOptions(args[1], args[2:], time.Now()); err != nil {
						t.Errorf("%s: %s: %v", file, line, err)
					}
				case "tcp":
					if _, err := parseTCPFlags(args[2:]); err != nil {
						t.Errorf("%s: %s: %v", file, line, err)
					}
				case "connector-check":
					if _, err := parseConnectorCheckFlags(args[2:]); err != nil {
						t.Errorf("%s: %s: %v", file, line, err)
					}
				case "mcp":
					if len(args) == 3 && args[2] == "--help" {
						continue
					}
					if _, err := parseMCPFlags(normalizeMCPArgs(args[2:])); err != nil {
						t.Errorf("%s: %s: %v", file, line, err)
					}
				default:
					if _, err := parseServeFlags(args[1:]); err != nil {
						t.Errorf("%s: %s: %v", file, line, err)
					}
				}
				checked++
			}
		}
	}
	if checked < 10 {
		t.Fatalf("checked only %d commands", checked)
	}
}
