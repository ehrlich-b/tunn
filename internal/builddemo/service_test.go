package builddemo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestBuildInvestigationRequiresRemoteEvidence(t *testing.T) {
	server := httptest.NewServer(NewHandler())
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := Investigate(ctx, ClientOptions{Endpoint: server.URL + "/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if report.ToolCalls != 7 || len(report.Evidence) != 6 || !strings.Contains(report.Recommendation, "before npm run build") {
		t.Fatalf("incomplete diagnosis: %+v", report)
	}
	for _, item := range report.Evidence {
		if !strings.Contains(item.Citation, ":") || item.Text == "" {
			t.Fatalf("missing citation or evidence text: %+v", item)
		}
	}
}

func TestBuildInvestigationRejectsContradictoryCI(t *testing.T) {
	documents := Documents()
	documents["ci/build.yml"] = "steps:\n  - run: npm ci\n  - run: npm run generate:schema\n  - run: npm run build\n"
	server := httptest.NewServer(NewHandlerWithDocuments(documents))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Investigate(ctx, ClientOptions{Endpoint: server.URL + "/mcp"}); err == nil || !strings.Contains(err.Error(), "CI already runs generation") {
		t.Fatalf("contradictory evidence should reject diagnosis, got %v", err)
	}
}

func TestBuildToolsRejectFilesystemAndEmptySearch(t *testing.T) {
	server := httptest.NewServer(NewHandler())
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "fixture-boundary-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 2 {
		t.Fatalf("tools = %v, error = %v", tools, err)
	}
	for _, tool := range tools.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("tool missing read-only hint: %+v", tool)
		}
	}
	for _, test := range []struct {
		name string
		args any
	}{
		{"build.read", ReadInput{Path: "../../.tunn/token"}},
		{"build.read", ReadInput{Path: "/etc/passwd"}},
		{"build.search", SearchInput{Query: " "}},
		{"build.search", SearchInput{Query: strings.Repeat("x", 257)}},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: test.name, Arguments: test.args})
		if err == nil && !result.IsError {
			t.Fatalf("%s accepted forbidden input %+v", test.name, test.args)
		}
	}
}

func TestBuildInvestigationHonorsConfiguredBearer(t *testing.T) {
	handler := NewHandler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-only" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Investigate(ctx, ClientOptions{Endpoint: server.URL + "/mcp"}); err == nil {
		t.Fatal("unauthenticated investigation succeeded")
	}
	client := &http.Client{Transport: bearerTransport{base: http.DefaultTransport}}
	if _, err := Investigate(ctx, ClientOptions{Endpoint: server.URL + "/mcp", HTTPClient: client}); err != nil {
		t.Fatal(err)
	}
}

type bearerTransport struct{ base http.RoundTripper }

func (transport bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer synthetic-only")
	return transport.base.RoundTrip(clone)
}
