package client

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyOwnerLoginSeparateBoundCredential(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(configDirectoryEnvironment, dir)
	// A durable publisher login already exists; management login must preserve it.
	for _, name := range []string{"token", credentialsFilename} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("publisher-unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	l := &LoginClient{PolicyOwner: true, ServerAddr: "relay.test", HTTPClient: &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Has("durable") || r.URL.Query().Get("code") != "authorized-fixture" {
			t.Error("owner requested scoped device exchange")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"owner-fixture","expires_in":86400,"token_type":"Bearer"}`)), Request: r}, nil
	})}}
	token, err := l.checkToken(context.Background(), "authorized-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.saveCredentials(token); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPolicyOwnerToken("https://relay.test")
	if err != nil || got != "owner-fixture" {
		t.Fatalf("owner load=%v", err)
	}
	if _, err = LoadPolicyOwnerToken("https://another.test"); err == nil {
		t.Fatal("owner credential escaped its login origin")
	}
	for _, name := range []string{"token", credentialsFilename} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != "publisher-unchanged" {
			t.Fatal("management login changed publisher credential")
		}
	}
	info, err := os.Stat(filepath.Join(dir, policyOwnerFilename))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("owner credential was not private")
	}
	if err = l.saveCredentials(&TokenResponse{AccessToken: "scoped", RefreshToken: "device", ExpiresIn: 86400}); err == nil {
		t.Fatal("owner accepted a renewable device token")
	}
	if err = os.Chmod(filepath.Join(dir, policyOwnerFilename), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPolicyOwnerToken("relay.test"); err == nil {
		t.Fatal("readable owner credential accepted")
	}
}

func TestPolicyOwnerLoginNeverFollowsExchangeRedirect(t *testing.T) {
	calls := 0
	l := &LoginClient{PolicyOwner: true, ServerAddr: "relay.test", HTTPClient: &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://other.test/owner-exchange"}}, Body: io.NopCloser(strings.NewReader("redirect")), Request: r}, nil
	})}}
	if _, err := l.checkToken(context.Background(), "owner-secret-code-fixture"); err == nil || calls != 1 {
		t.Fatalf("owner exchange followed redirect: %v calls=%d", err, calls)
	}
}
