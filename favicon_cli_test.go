package main

import "testing"

func TestFaviconCLI(t *testing.T) {
	o, err := parseServeFlags([]string{"3000", "--no-favicon"})
	if err != nil || !o.noFavicon {
		t.Fatalf("serve: %v %v", o, err)
	}
	m, err := parseMCPFlags([]string{"--no-favicon", "http://localhost:3000/mcp"})
	if err != nil || !m.noFavicon {
		t.Fatalf("mcp: %v %v", m, err)
	}
}
