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
	"time"
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
	for _, args := range [][]string{{"add", "*.apps.example.com"}, {"add", "*.apps.example.com", "--tunnel", "dashboard"}, {"verify", "*.apps.example.com"}, {"delete", "*.apps.example.com"}} {
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

func TestDomainManagementUsesOwnerLogin(t *testing.T) {
	t.Setenv("TUNN_ENV", "dev")
	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("scoped-publisher-token"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/api/domains" || r.Header.Get("Authorization") != "Bearer separate-owner-token" {
			t.Errorf("wrong domain credential or request: %s %s", r.Method, r.URL.Path)
		}
		io.WriteString(w, `{"domains":[]}`)
	}))
	defer server.Close()
	args := []string{"list", "--server", server.URL, "--insecure"}
	// A publisher login alone must not be sent to a domain management API.
	if err := executeDomains(args, io.Discard); err == nil || !strings.Contains(err.Error(), "tunn policy login") {
		t.Errorf("missing owner-login guidance: %v", err)
	}
	if calls != 0 {
		t.Fatalf("publisher credential sent to management API: %d calls", calls)
	}
	saveOwner := func(origin string) {
		data, err := json.Marshal(map[string]any{"server": origin, "access_token": "separate-owner-token", "expires_at": "2099-01-01T00:00:00Z"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "policy-owner.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	saveOwner(server.URL)
	if err := executeDomains(args, io.Discard); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("owner domain listing: %d calls", calls)
	}
	saveOwner("https://another-relay.example.test")
	if err := executeDomains(args, io.Discard); err == nil || !strings.Contains(err.Error(), "another relay") {
		t.Errorf("wrong-origin owner credential accepted: %v", err)
	}
	if calls != 1 {
		t.Fatal("owner credential sent to a different origin")
	}
}

func TestDomainExplicitOwnerLoginFile(t *testing.T) {
	t.Setenv("TUNN_ENV", "dev")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-owner-token" {
			t.Error("wrong owner credential")
		}
		io.WriteString(w, `{}`)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "policy-owner.json")
	data, _ := json.Marshal(map[string]any{"server": server.URL, "access_token": "fixture-owner-token", "expires_at": time.Now().Add(time.Hour)})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := executeDomains([]string{"add", "*.apps.example.com", "--tunnel", "openfront", "--server", server.URL, "--owner-token-file", path, "--insecure"}, io.Discard); err != nil {
		t.Fatal(err)
	}
}
