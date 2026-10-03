package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestInvestigatorDoesNotFollowCredentialRedirect(t *testing.T) {
	var redirectedCalls atomic.Int64
	otherEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedCalls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer otherEndpoint.Close()
	// Changing the hostname as well as the port crosses origins. Both targets
	// remain loopback; no external request is possible in this regression.
	redirectURL := strings.Replace(otherEndpoint.URL, "127.0.0.1", "localhost", 1) + "/mcp"
	originalEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
	}))
	defer originalEndpoint.Close()
	tokenFile := filepath.Join(t.TempDir(), "synthetic.token")
	if err := os.WriteFile(tokenFile, []byte("synthetic-redirect-test-only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"build-investigation", "investigate", "--endpoint", originalEndpoint.URL + "/mcp", "--token-file", tokenFile}
	if err := run(); err == nil {
		t.Fatal("redirecting MCP endpoint produced a successful investigation")
	}
	if calls := redirectedCalls.Load(); calls != 0 {
		t.Fatalf("investigator followed a cross-origin credential redirect (%d requests)", calls)
	}
}
