package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGrantClientDoesNotForwardCredentialsOnRedirect(t *testing.T) {
	forwarded := false
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true; t.Error("redirect followed") }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer server.Close()
	api := &GrantClient{BaseURL: server.URL, OwnerToken: "synthetic-owner-token", HTTPClient: server.Client()}
	_, _, err := api.Create(context.Background(), "build", "client", time.Minute, 20)
	if err == nil || forwarded || strings.Contains(err.Error(), api.OwnerToken) {
		t.Fatalf("unsafe redirect/error: %v", err)
	}
}

func TestGrantClientRejectsUnsafeOrigins(t *testing.T) {
	for _, origin := range []string{"http://localhost", "https://user:pass@example.test", "https://example.test/path", "https://example.test?token=secret", "https://example.test#fragment"} {
		api := &GrantClient{BaseURL: origin, OwnerToken: "synthetic-owner-token"}
		if _, err := api.List(context.Background(), ""); err == nil {
			t.Errorf("unsafe origin accepted: %s", origin)
		}
	}
}
