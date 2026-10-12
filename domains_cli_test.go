package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDomainOptions(t *testing.T) {
	for _, args := range [][]string{
		{"add", "Work.Example.com.", "--tunnel", "site", "--server=https://relay.test", "--owner-token-file", "owner"},
		{"verify", "--server", "relay.test", "work.example.com"},
		{"list", "--insecure"}, {"delete", "work.example.com"},
	} {
		o, err := parseDomainOptions(args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if o.action != "list" && o.name != "work.example.com" {
			t.Fatal(o)
		}
	}
	for _, args := range [][]string{{}, {"unknown"}, {"add", "work.example.com"}, {"add", "https://work.example.com", "--tunnel", "site"}, {"list", "work.example.com"}, {"delete", "../secret"}, {"verify", "work.example.com", "--server"}, {"add", "work.example.com", "--tunnel", "-site"}, {"verify", "work.example.com", "--tunnel", "site"}} {
		if _, err := parseDomainOptions(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if _, err := parseDomainOptions([]string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
}

func TestParseWildcardDomainOptions(t *testing.T) {
	for _, args := range [][]string{{"add", "*.apps.ehrlich.dev"}, {"add", "*.apps.ehrlich.dev", "--tunnel", "dashboard"}, {"verify", "*.apps.ehrlich.dev"}, {"delete", "*.apps.ehrlich.dev"}} {
		if _, err := parseDomainOptions(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestDomainCLIReportsCompetingProof(t *testing.T) {
	t.Setenv("TUNN_ENV", "dev")
	tokenFile := filepath.Join(t.TempDir(), "owner-token")
	if err := os.WriteFile(tokenFile, []byte("owner-token"), 0600); err != nil {
		t.Fatal(err)
	}
	const instructions = "unverified claim: prove ownership with TXT _tunn-verification.apps.example.com = dv-caller.tunn.test and retry add within 24 hours"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/domains" || r.Header.Get("Authorization") != "Bearer owner-token" {
			t.Errorf("unexpected owner API request: %s %s", r.Method, r.URL.Path)
		}
		var input struct{ Name, Tunnel string }
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Name != "*.apps.example.com" || input.Tunnel != "dashboard" {
			t.Errorf("unexpected domain binding: %+v err=%v", input, err)
		}
		http.Error(w, instructions, http.StatusConflict)
	}))
	defer server.Close()
	// runDomains prints this error verbatim to stderr.
	err := executeDomains([]string{"add", "*.apps.example.com", "--tunnel", "dashboard", "--server", server.URL, "--owner-token-file", tokenFile}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "HTTP 409: "+instructions) {
		t.Fatalf("CLI discarded competing proof instructions: %v", err)
	}
}

func TestNamespaceServeFlag(t *testing.T) {
	o, err := parseServeFlags([]string{"--namespace", "apps.customer.test", "--name", "grafana", "3000"})
	if err != nil || o.namespace != "apps.customer.test" || o.tunnelID != "grafana" {
		t.Fatalf("namespace flags: %+v %v", o, err)
	}
	for _, args := range [][]string{{"--namespace", "apps.customer.test", "3000"}, {"--namespace", "https://apps.customer.test", "--name", "grafana", "3000"}, {"--namespace", "apps.customer.test", "--name", "www", "3000"}} {
		if _, err := parseServeFlags(args); err == nil {
			t.Fatalf("accepted invalid namespace publication: %v", args)
		}
	}
}
