package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ehrlich-b/tunn/internal/trafficpolicy"
)

func TestPolicyCLIParsesInterspersedAndRejectsIncompleteCommands(t *testing.T) {
	for _, args := range [][]string{{"login"}, {"login", "--server", "https://relay.test"}, {"get", "api"}, {"clear", "--server", "https://relay.test", "api"}, {"set", "api", "--file", "policy.json"}, {"set", "--file=policy.json", "api"}} {
		if _, err := parsePolicyOptions(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{}, {"login", "api"}, {"login", "--owner-token-file", "owner"}, {"unknown", "api"}, {"set", "api"}, {"set", "../api", "--file", "p.json"}, {"get", "api", "--file", "p.json"}, {"get", "api", "other"}} {
		if _, err := parsePolicyOptions(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestPolicyCLIExecutesFileAndOwnerAPI(t *testing.T) {
	t.Setenv("TUNN_ENV", "dev")
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "owner-token")
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(tokenPath, []byte("owner-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`{"headers":{"remove":["X-Test"]},"rate_limits":{"per_ip":{"requests_per_minute":60,"burst":2}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/endpoints/api/policy" || r.Method != "PUT" || r.Header.Get("Authorization") != "Bearer owner-fixture" {
			t.Error("incorrect owner request")
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if _, err = trafficpolicy.Decode(data); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	defer server.Close()
	args := []string{"set", "api", "--file", policyPath, "--server", server.URL, "--owner-token-file", tokenPath}
	var out bytes.Buffer
	if err := executePolicy(args, &out); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || out.Len() == 0 {
		t.Fatal("CLI did not call API")
	}
	if err := os.WriteFile(policyPath, []byte(`{"headers":{"remove":["Tunn-Authorization"]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := executePolicy(args, io.Discard); err == nil || calls != 1 {
		t.Fatal("invalid file reached API")
	}
}
