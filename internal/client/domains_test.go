package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDomainClientUsesOwnerOriginAndRefusesRedirects(t *testing.T) {
	calls := 0
	c := &ManagementClient{ServerURL: "https://relay.test", OwnerToken: "owner-secret", HTTPClient: &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "relay.test" || r.Header.Get("Authorization") != "Bearer owner-secret" {
			return nil, fmt.Errorf("credential escaped owner origin")
		}
		switch r.URL.Path {
		case "/api/domains":
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"domains":[]}`)), Request: r}, nil
		case "/api/domains/work.example.com/verify":
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://other.example.com/steal"}}, Body: io.NopCloser(strings.NewReader("redirect")), Request: r}, nil
		case "/api/domains/work.example.com":
			return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		default:
			return nil, fmt.Errorf("unexpected path %s", r.URL.Path)
		}
	})}}
	if _, err := c.DomainCall(context.Background(), "GET", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DomainCall(context.Background(), "POST", "Work.Example.com.", "verify", nil); err == nil {
		t.Fatal("redirect accepted")
	}
	if calls != 2 {
		t.Fatal("redirect followed", calls)
	}
	if _, err := c.DomainCall(context.Background(), "DELETE", "work.example.com", "", nil); err != nil {
		t.Fatal(err)
	}
	for _, server := range []string{"http://relay.test", "https://owner@relay.test", "https://relay.test/path"} {
		c.ServerURL = server
		if _, err := c.DomainCall(context.Background(), "GET", "", "", nil); err == nil {
			t.Fatal(server)
		}
	}
	if _, err := c.DomainCall(context.Background(), "DELETE", "../account", "", nil); err == nil {
		t.Fatal("invalid domain path accepted")
	}
}

func TestNamespacePublisherLookupPreservesLegacyAndScopedIDs(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			tunnel := "ns-012345678901234567890123456789012345678901234567"
			if legacy {
				tunnel = "grafana"
			}
			statusCode := 200
			body := fmt.Sprintf(`{"tunnel":%q}`, tunnel)
			c := &ManagementClient{ServerURL: "https://relay.test", OwnerToken: "publisher-fixture", HTTPClient: &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
				var input struct {
					Name string `json:"name"`
				}
				if r.Method != "POST" || r.URL.Path != "/api/domains/publisher" || r.Header.Get("Authorization") != "Bearer publisher-fixture" || json.NewDecoder(r.Body).Decode(&input) != nil || input.Name != "grafana.apps.customer.test" {
					t.Fatalf("unexpected lookup: %s %s", r.Method, r.URL.Path)
				}
				return &http.Response{StatusCode: statusCode, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}}
			if got, err := c.NamespaceTunnel(context.Background(), "APPS.Customer.Test.", "grafana"); err != nil || got != tunnel {
				t.Fatalf("lookup=%s %v", got, err)
			}
			statusCode = 403
			if _, err := c.NamespaceTunnel(context.Background(), "apps.customer.test", "grafana"); err == nil {
				t.Fatal("denied lookup succeeded")
			}
			statusCode = 200
			body = `{"tunnel":"../invalid"}`
			if _, err := c.NamespaceTunnel(context.Background(), "apps.customer.test", "grafana"); err == nil {
				t.Fatal("invalid publisher ID accepted")
			}
		})
	}
}
