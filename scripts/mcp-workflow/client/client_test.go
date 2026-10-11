package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/scripts/mcp-workflow/client"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (brokenBody) Close() error             { return nil }
func TestFailuresAreTypedAndSecretFree(t *testing.T) {
	const private = "PRIVATE-PROMPT-TOKEN-SENTINEL"
	cases := []struct {
		name              string
		status            int
		media, body, code string
		broken            bool
	}{
		{"no service", 503, "application/json", private, "service_unavailable", false},
		{"revoked or expired", 401, "application/json", private, "access_denied", false},
		{"wrong endpoint", 404, "text/plain", private, "wrong_endpoint", false},
		{"redirect refused", 302, "text/html", private, "protocol_error", false},
		{"truncated json", 200, "application/json", `{"jsonrpc":"2.0","id":1,"result":`, "incomplete_response", false},
		{"body interrupted", 200, "application/json", "", "incomplete_response", true},
		{"missing result", 200, "application/json", `{"jsonrpc":"2.0","id":1}`, "incomplete_response", false},
		{"empty answer", 200, "application/json", `{"jsonrpc":"2.0","id":1,"result":{}}`, "incomplete_response", false},
		{"null result", 200, "application/json", `{"jsonrpc":"2.0","id":1,"result":null}`, "incomplete_response", false},
		{"wrong id", 200, "application/json", `{"jsonrpc":"2.0","id":2,"result":{}}`, "protocol_error", false},
		{"remote rpc error", 200, "application/json", `{"jsonrpc":"2.0","id":1,"error":{"message":"` + private + `"}}`, "protocol_error", false},
		{"tool error", 200, "application/json", `{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"` + private + `"}]}}`, "tool_error", false},
		{"truncated sse", 200, "text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n", "incomplete_response", false},
		{"duplicate sse", 200, "text/event-stream", "data: {}\n\ndata: {}\n\n", "incomplete_response", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport := transportFunc(func(r *http.Request) (*http.Response, error) {
				if !strings.Contains(r.Header.Get("Authorization"), private) {
					t.Fatal("bearer not supplied")
				}
				var body io.ReadCloser = io.NopCloser(strings.NewReader(tc.body))
				if tc.broken {
					body = brokenBody{}
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {tc.media}}, Body: body, Request: r}, nil
			})
			c := client.Consumer{HTTP: &http.Client{Transport: transport}, Endpoint: "https://reader.invalid/mcp", Bearer: private}
			raw, err := c.Tool(context.Background(), 1, "project_search", map[string]any{"query": private})
			var failure *client.Failure
			if raw != nil || !errors.As(err, &failure) || failure.Code != tc.code || failure.Instruction == "" {
				t.Fatalf("failure classification %v", err)
			}
			if strings.Contains(err.Error()+failure.Instruction, private) {
				t.Fatal("private body or token entered diagnostic")
			}
		})
	}
}
func TestUnavailableTransportAndCancellation(t *testing.T) {
	c := client.Consumer{HTTP: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("secret underlying connection failure")
	})}, Endpoint: "https://reader.invalid/mcp"}
	for _, cancel := range []bool{false, true} {
		ctx, stop := context.WithCancel(context.Background())
		if cancel {
			stop()
		}
		_, err := c.Tool(ctx, 1, "project_list", map[string]any{})
		stop()
		var f *client.Failure
		if !errors.As(err, &f) {
			t.Fatal("untyped error")
		}
		want := "service_unavailable"
		if cancel {
			want = "canceled"
		}
		if f.Code != want || strings.Contains(err.Error(), "secret") {
			t.Fatal("failure classification unsafe")
		}
	}
}

type cancelBody struct{ stop context.CancelFunc }

func (b cancelBody) Read([]byte) (int, error) { b.stop(); return 0, context.Canceled }
func (b cancelBody) Close() error             { return nil }
func TestCancellationAfterHeaders(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	c := client.Consumer{HTTP: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: cancelBody{stop}, Request: r}, nil
	})}, Endpoint: "https://reader.invalid/mcp"}
	raw, err := c.Tool(ctx, 1, "project_list", map[string]any{})
	var f *client.Failure
	if raw != nil || !errors.As(err, &f) || f.Code != "canceled" {
		t.Fatal("body cancellation misreported")
	}
}
func TestInitializedNotification(t *testing.T) {
	for _, status := range []int{202, 200, 401} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c := client.Consumer{HTTP: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), `"id"`) || !strings.Contains(string(body), "notifications/initialized") {
					t.Fatal("notification has wrong shape")
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
			})}, Endpoint: "https://reader.invalid/mcp"}
			err := c.Initialized(context.Background())
			if (err == nil) != (status == 202) {
				t.Fatal("notification status was not validated")
			}
		})
	}
}
