package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/trafficpolicy"
)

func TestPolicyClientOwnerContractAndNoRedirect(t *testing.T) {
	methods := []string{}
	c := &ManagementClient{ServerURL: "https://relay.test", OwnerToken: "owner-fixture", HTTPClient: &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		methods = append(methods, r.Method)
		if r.URL.Path != "/api/endpoints/api/policy" || r.URL.Host != "relay.test" || r.Header.Get("Authorization") != "Bearer owner-fixture" {
			return nil, fmt.Errorf("unexpected owner request")
		}
		if r.Method == http.MethodPut {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			if _, err = trafficpolicy.Decode(data); err != nil {
				return nil, err
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"headers":{},"rate_limits":{}}`)), Request: r}, nil
	})}}
	for _, action := range []string{"set", "get", "clear"} {
		var out bytes.Buffer
		if err := ExecutePolicy(context.Background(), action, "api", &trafficpolicy.Policy{}, c, &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "rate_limits") {
			t.Fatal(out.String())
		}
	}
	if strings.Join(methods, ",") != "PUT,GET,DELETE" {
		t.Fatal(methods)
	}
	calls := 0
	c.HTTPClient.Transport = meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://elsewhere.test/"}}, Body: io.NopCloser(strings.NewReader("redirect")), Request: r}, nil
	})
	if err := ExecutePolicy(context.Background(), "get", "api", nil, c, io.Discard); err == nil || calls != 1 {
		t.Fatalf("redirect followed: %v %d", err, calls)
	}
	c.ServerURL = "http://relay.test"
	if err := ExecutePolicy(context.Background(), "get", "api", nil, c, io.Discard); err == nil || calls != 1 {
		t.Fatal("credential sent without HTTPS")
	}
}
