package main

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Validate the commands readers copy from the actual pages without logging in,
// downloading an MCP server, publishing an endpoint, or opening any listener.
func TestDistributionCLICommands(t *testing.T) {
	files, err := filepath.Glob("internal/host/templates/*-*.html")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile(`(?s)<pre><code>(.*?)</code></pre>`)
	var checked int
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, block := range blocks.FindAllStringSubmatch(string(data), -1) {
			for _, line := range strings.Split(html.UnescapeString(block[1]), "\n") {
				args := strings.Fields(line)
				if len(args) < 2 || args[0] != "tunn" {
					continue
				}
				switch args[1] {
				case "login":
					if len(args) != 2 {
						t.Errorf("unexpected login arguments: %s", line)
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
