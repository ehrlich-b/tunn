package main

import (
	"reflect"
	"testing"
)

func TestParseMCPFlags(t *testing.T) {
	opts, err := parseMCPFlags([]string{
		"--name", "work-tools",
		"--allow", "alice@example.com, bob@example.com",
		"--",
		"docker", "mcp", "gateway", "run", "--profile", "work",
	})
	if err != nil {
		t.Fatalf("parseMCPFlags: %v", err)
	}
	if opts.tunnelID != "work-tools" {
		t.Fatalf("tunnelID = %q, want work-tools", opts.tunnelID)
	}
	if want := []string{"alice@example.com", "bob@example.com"}; !reflect.DeepEqual(opts.allowedEmails, want) {
		t.Fatalf("allowedEmails = %#v, want %#v", opts.allowedEmails, want)
	}
	if want := []string{"docker", "mcp", "gateway", "run", "--profile", "work"}; !reflect.DeepEqual(opts.command, want) {
		t.Fatalf("command = %#v, want %#v", opts.command, want)
	}
}

func TestParseMCPFlagsRequiresDelimiter(t *testing.T) {
	if _, err := parseMCPFlags([]string{"npx", "server"}); err == nil {
		t.Fatal("parseMCPFlags accepted multiple non-command arguments")
	}
	if _, err := parseMCPFlags([]string{"--"}); err == nil {
		t.Fatal("parseMCPFlags succeeded without a command")
	}
}

func TestParseMCPHTTPURL(t *testing.T) {
	opts, err := parseMCPFlags([]string{"--name", "networked", "http://127.0.0.1:3000/custom-mcp"})
	if err != nil {
		t.Fatalf("parseMCPFlags: %v", err)
	}
	if opts.targetURL != "http://127.0.0.1:3000/custom-mcp" || len(opts.command) != 0 {
		t.Fatalf("unexpected HTTP options: %#v", opts)
	}
}

func TestSplitMCPUpstreamURL(t *testing.T) {
	base, path, query, err := splitMCPUpstreamURL("https://localhost:8443/custom/mcp?tenant=one")
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://localhost:8443" || path != "/custom/mcp" || query != "tenant=one" {
		t.Fatalf("split = %q, %q, %q", base, path, query)
	}

	base, path, query, err = splitMCPUpstreamURL("http://localhost:3000")
	if err != nil || base != "http://localhost:3000" || path != "/mcp" || query != "" {
		t.Fatalf("default split = %q, %q, %q, %v", base, path, query, err)
	}

	for _, invalid := range []string{"stdio://server", "localhost:3000/mcp", "http://user:pass@localhost/mcp", "http://localhost/mcp#fragment"} {
		if _, _, _, err := splitMCPUpstreamURL(invalid); err == nil {
			t.Errorf("accepted invalid MCP URL %q", invalid)
		}
	}
}

func TestParseMCPFlagsRejectsPublicAllowList(t *testing.T) {
	if _, err := parseMCPFlags([]string{"--public", "--allow", "alice@example.com", "--", "server"}); err == nil {
		t.Fatal("parseMCPFlags accepted --public with --allow")
	}
}

func TestParseMCPToolAllowList(t *testing.T) {
	opts, err := parseMCPFlags([]string{"--tools", "read_file, list_directory", "--", "server"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"read_file", "list_directory"}
	if !reflect.DeepEqual(opts.allowedTools, want) {
		t.Fatalf("allowed tools = %#v, want %#v", opts.allowedTools, want)
	}
}

func TestAppendUniqueEmail(t *testing.T) {
	emails := appendUniqueEmail([]string{"Alice@Example.com"}, " alice@example.com ")
	if len(emails) != 1 {
		t.Fatalf("duplicate email was appended: %#v", emails)
	}
	emails = appendUniqueEmail(emails, "bob@example.com")
	if len(emails) != 2 || emails[1] != "bob@example.com" {
		t.Fatalf("new email was not appended: %#v", emails)
	}
}

func TestParseTCPFlags(t *testing.T) {
	opts, err := parseTCPFlags([]string{"--name", "database", "5432"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.tunnelID != "database" || opts.target != "127.0.0.1:5432" {
		t.Fatalf("TCP options = %#v", opts)
	}
	if _, err := parseTCPFlags([]string{"localhost"}); err == nil {
		t.Fatal("accepted TCP target without port")
	}
}

func TestParseUnixFlags(t *testing.T) {
	opts, err := parseUnixFlags([]string{"--name", "docker", "/var/run/docker.sock"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.tunnelID != "docker" || opts.target != "/var/run/docker.sock" {
		t.Fatalf("Unix options = %#v", opts)
	}
	if _, err := parseUnixFlags([]string{"relative.sock"}); err == nil {
		t.Fatal("accepted relative Unix socket")
	}
	httpOpts, err := parseUnixFlags([]string{"--as", "http", "/var/run/docker.sock"})
	if err != nil || httpOpts.adapter != "http" {
		t.Fatalf("HTTP Unix options = %#v, %v", httpOpts, err)
	}
	if _, err := parseUnixFlags([]string{"--as", "http", "--public", "/var/run/docker.sock"}); err == nil {
		t.Fatal("accepted public HTTP-over-Unix endpoint")
	}
}

func TestResolveConnectEndpoint(t *testing.T) {
	endpoint, name, err := resolveConnectEndpoint("database", "tunn.local", "tunn.to:443")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://database.tunn.to/_tunn/connect" || name != "database" {
		t.Fatalf("resolved endpoint = %q, %q", endpoint, name)
	}
	endpoint, _, err = resolveConnectEndpoint("https://db.example.test/ignored?query=yes", "", "")
	if err != nil || endpoint != "https://db.example.test/_tunn/connect" {
		t.Fatalf("resolved URL = %q, %v", endpoint, err)
	}
	_, name, err = resolveConnectEndpoint("https://database.evil.example", "", "")
	if err != nil || name != "" {
		t.Fatalf("explicit URL offered token auto-load: name=%q err=%v", name, err)
	}
	if _, _, err := resolveConnectEndpoint("http://database.example", "", ""); err == nil {
		t.Fatal("accepted plaintext remote endpoint URL")
	}
}
