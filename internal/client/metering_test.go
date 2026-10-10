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

type meteringTransportFunc func(*http.Request) (*http.Response, error)

func (f meteringTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestMeteringManagementClientSendsOnlyDigestAndOwnerCredential(t *testing.T) {
	calls := 0
	transport := meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://127.0.0.1:8443/api/endpoints/api/grants" || r.Header.Get("Authorization") != "Bearer owner-jwt" {
			t.Fatalf("request=%v headers=%v", r.URL, r.Header)
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "consumer-secret") {
			t.Fatal("consumer token sent")
		}
		return &http.Response{StatusCode: 201, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"grant-id"}`)), Request: r}, nil
	})
	c := &ManagementClient{ServerURL: "127.0.0.1:8443", OwnerToken: "owner-jwt\n", HTTPClient: &http.Client{Transport: transport}}
	out, err := c.Call(context.Background(), "POST", "api", "grants", map[string]any{"token_sha256": "digest", "monthly_bytes": 100})
	if err != nil || !json.Valid(out) || calls != 1 {
		t.Fatalf("response=%s calls=%d %v", out, calls, err)
	}
}
func TestMeteringManagementClientConfinementAndRedirects(t *testing.T) {
	calls := 0
	transport := meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://other.example/steal"}}, Body: io.NopCloser(strings.NewReader("redirect")), Request: r}, nil
	})
	for _, server := range []string{"http://remote.example", "https://user:password@example.com", "file:///tmp/secret", "https://host/path", "https://host?query=yes"} {
		c := &ManagementClient{ServerURL: server, HTTPClient: &http.Client{Transport: transport}}
		if _, err := c.Call(context.Background(), "GET", "api", "usage", nil); err == nil {
			t.Fatalf("accepted server %s", server)
		}
	}
	if calls != 0 {
		t.Fatal("unsafe origin received credential")
	}
	c := &ManagementClient{ServerURL: "http://127.0.0.1:8443", OwnerToken: "owner-jwt", HTTPClient: &http.Client{Transport: transport}}
	if _, err := c.Call(context.Background(), "GET", "../api", "usage", nil); err == nil {
		t.Fatal("accepted path injection")
	}
	if _, err := c.Call(context.Background(), "GET", "api", "usage", nil); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect error=%v", err)
	}
	if calls != 1 {
		t.Fatal("redirect followed")
	}
}
func TestMeteringManagementClientHandlesBadResponses(t *testing.T) {
	for _, fixture := range []struct {
		status int
		body   string
	}{{403, "Access denied"}, {200, "not-json"}} {
		t.Run(fmt.Sprint(fixture.status), func(t *testing.T) {
			c := &ManagementClient{ServerURL: "https://relay.test", OwnerToken: "owner-jwt", HTTPClient: &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: fixture.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(fixture.body)), Request: r}, nil
			})}}
			if _, err := c.Call(context.Background(), "GET", "api", "usage", nil); err == nil {
				t.Fatal("accepted invalid response")
			}
		})
	}
}

func TestMeteringManagementClientOwnerUsageAndGrantList(t *testing.T) {
	for _, operation := range []string{"usage?since=24h", "grants"} {
		c := &ManagementClient{ServerURL: "http://127.0.0.1:8443", OwnerToken: "owner-jwt", HTTPClient: &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "http://127.0.0.1:8443/api/"+operation || r.Header.Get("Authorization") != "Bearer owner-jwt" {
				t.Fatalf("request=%v", r)
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
		})}}
		if _, err := c.Call(context.Background(), "GET", "", operation, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Call(context.Background(), "POST", "", "grants", nil); err == nil {
			t.Fatal("accepted endpoint-free write")
		}
	}
}
