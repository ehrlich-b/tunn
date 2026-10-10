package client

import (
	"context"
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
