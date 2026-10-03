package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/client"
)

func TestMCPCheckCommandEmitsFailureJSONWithoutCredentials(t *testing.T) {
	var output, diagnostics bytes.Buffer
	err := executeMCPCheck(context.Background(), []string{"https://user:private-token@example.invalid/mcp"}, &output, &diagnostics)
	if err == nil {
		t.Fatal("unsafe input accepted")
	}
	var report client.MCPCheckReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.Ready || len(report.Checks) == 0 {
		t.Fatalf("failure JSON %s, decode error %v", output.String(), err)
	}
	if strings.Contains(output.String()+diagnostics.String()+err.Error(), "private-token") {
		t.Fatal("unsafe URL credential echoed")
	}
}

func TestMCPCheckCommandRequiresExplicitEndpoint(t *testing.T) {
	for _, args := range [][]string{nil, {"--issuer", "https://example.invalid"}, {"https://example.invalid/mcp", "extra"}} {
		if err := executeMCPCheck(context.Background(), args, new(bytes.Buffer), new(bytes.Buffer)); err == nil {
			t.Fatalf("accepted arguments %v", args)
		}
	}
}

func TestMCPCheckCommandUsesAdditionalCA(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("unexpected authenticated or mutating request: %s", r.Method)
		}
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, server.URL))
			w.WriteHeader(401)
		case "/.well-known/oauth-protected-resource/mcp":
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": server.URL + "/mcp", "authorization_servers": []string{server.URL}, "scopes_supported": []string{"mcp:access"}})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "authorization_endpoint": server.URL + "/oauth/authorize", "token_endpoint": server.URL + "/oauth/token",
				"token_endpoint_auth_methods_supported": []string{"none"}, "code_challenge_methods_supported": []string{"S256"},
				"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"},
				"scopes_supported": []string{"mcp:access"}, "authorization_response_iss_parameter_supported": true,
			})
		default:
			t.Errorf("unexpected non-discovery request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	err := executeMCPCheck(context.Background(), []string{"--issuer", server.URL, "--ca-cert", caPath, server.URL + "/mcp"}, &output, &diagnostics)
	var report client.MCPCheckReport
	if decodeErr := json.Unmarshal(output.Bytes(), &report); err != nil || decodeErr != nil || !report.Ready || diagnostics.Len() != 0 {
		t.Fatalf("command error %v, decode %v, report %+v, diagnostics %s", err, decodeErr, report, diagnostics.String())
	}
}
