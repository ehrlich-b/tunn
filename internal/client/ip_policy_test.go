package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type ipPolicyTransport func(*http.Request) (*http.Response, error)

func (f ipPolicyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestIPPolicyManagementTransport(t *testing.T) {
	for _, tt := range []struct{ action, endpoint, method, path string }{
		{"get", "", "GET", "/api/ip-policy"}, {"get", "app", "GET", "/api/ip-policy/app"},
		{"set", "app", "PUT", "/api/ip-policy/app"}, {"clear", "app", "DELETE", "/api/ip-policy/app"},
	} {
		called := false
		c := &ManagementClient{ServerURL: "https://relay.example.invalid", OwnerToken: "fixture-owner", HTTPClient: &http.Client{Transport: ipPolicyTransport(func(r *http.Request) (*http.Response, error) {
			called = true
			if r.Method != tt.method || r.URL.Path != tt.path || r.Header.Get("Authorization") != "Bearer fixture-owner" {
				t.Fatal(r)
			}
			if tt.action == "set" {
				data, _ := io.ReadAll(r.Body)
				if !strings.Contains(string(data), "192.0.2.0/24") || !strings.Contains(string(data), "deny_cidrs") {
					t.Fatal(string(data))
				}
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"configured":true}`))}, nil
		})}}
		if _, err := c.IPPolicy(context.Background(), tt.action, tt.endpoint, []string{"192.0.2.0/24"}, nil); err != nil || !called {
			t.Fatal(err)
		}
	}
	for _, server := range []string{"http://remote.example.invalid", "https://user:password@relay.example.invalid", "https://relay.example.invalid/path"} {
		c := &ManagementClient{ServerURL: server, OwnerToken: "fixture-owner"}
		if _, err := c.IPPolicy(context.Background(), "get", "app", nil, nil); err == nil {
			t.Fatal("unsafe origin", server)
		}
	}
	c := &ManagementClient{ServerURL: "https://relay.example.invalid", OwnerToken: "fixture-owner", HTTPClient: &http.Client{Transport: ipPolicyTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "relay.example.invalid" {
			t.Fatal("credential redirect followed")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://other.example.invalid"}}, Body: io.NopCloser(strings.NewReader("redirect"))}, nil
	})}}
	if _, err := c.IPPolicy(context.Background(), "get", "app", nil, nil); err == nil {
		t.Fatal("redirect accepted")
	}
	if _, err := c.IPPolicy(context.Background(), "get", "bad/name", nil, nil); err == nil {
		t.Fatal("invalid endpoint")
	}
}
