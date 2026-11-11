package host

import (
	"html"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
)

func TestConnectorGuideRoutes(t *testing.T) {
	cfg := &config.Config{Domain: "tunn.to", StatusURL: "http://127.0.0.1:8091"}
	p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
	handler := p.createHandler()
	var canonical string
	for _, path := range []string{"/mcp-to-claude", "/docs/mcp-to-claude"} {
		for _, method := range []string{"GET", "HEAD", "POST"} {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(method, "https://tunn.to"+path, nil))
			if method == "POST" {
				if w.Code != 405 {
					t.Errorf("%s accepted POST", path)
				}
				continue
			}
			if w.Code != 200 {
				t.Errorf("%s %s status %d", method, path, w.Code)
			}
			if method == "HEAD" {
				if w.Body.Len() != 0 {
					t.Errorf("%s HEAD body", path)
				}
				continue
			}
			if path == "/mcp-to-claude" {
				canonical = w.Body.String()
			}
			if w.Body.String() != canonical {
				t.Errorf("%s differs from canonical guide", path)
			}
		}
	}
	for _, want := range []string{"Claude.ai and ChatGPT", "connector-check --oauth --expect-tools echo", "--deny-tool hidden_echo", "25 seconds", "27 seconds", "have not yet been verified end to end", "/pricing", "/account/mcp", "Access tokens expire after one hour", "single-use refresh token", "up to 30 days after consent", "Clients without refresh"} {
		if !strings.Contains(mcpToClaudeHTML, want) {
			t.Errorf("guide missing %q", want)
		}
	}
}

func TestMCPToClaudeVerified(t *testing.T) {
	const experimental = "Experimental: connections to Claude.ai and ChatGPT have not yet been verified end to end."
	const account = " You need an account that supports custom MCP connectors.</p>"
	longClients := []string{
		"Claude.ai web on macOS with a personal account 2026-11-12",
		"Claude iOS on iPhone with a personal account 2026-11-12",
		"Claude Android on a Pixel with a personal account 2026-11-12",
		"Claude Desktop on macOS with a personal account 2026-11-12",
		"Claude Desktop on Windows with a personal account 2026-11-12",
		"ChatGPT web on macOS with a personal account 2026-11-12",
		"ChatGPT iOS on iPhone with a personal account 2026-11-12",
		"ChatGPT Android on a Pixel with a personal account 2026-11-12",
	}
	for _, tc := range []struct{ name, value string }{
		{"unset", ""},
		{"whitespace", " \t\n\r\u2003"},
		{"one", "Claude.ai web 2026-11-12"},
		{"multiple", "Claude.ai web 2026-11-12; Claude iOS 2026-11-12"},
		{"escaped", `<script>alert("client")</script> & <img src=x onerror=alert(1)> {{.MCPVerified}}`},
		{"long", strings.Join(longClients, "; ")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Domain: "tunn.to", MCPVerified: tc.value}
			p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
			handler := p.createHandler()
			for _, path := range []string{"/mcp-to-claude", "/docs/mcp-to-claude"} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to"+path, nil))
				if w.Code != 200 {
					t.Fatalf("%s: status %d", path, w.Code)
				}
				body := w.Body.String()
				value := strings.TrimSpace(tc.value)
				want := experimental
				if value != "" {
					want = "Verified with: " + html.EscapeString(value) + "."
				}
				if !strings.Contains(body, `<p class="note">`+want+account) {
					t.Errorf("%s: missing exact escaped note %q", path, want)
				}
				if value == "" && strings.Contains(body, "Verified with:") || value != "" && strings.Contains(body, experimental) {
					t.Errorf("%s: wrong verification state", path)
				}
				if dir := os.Getenv("TUNN_MCP_PREVIEW_DIR"); dir != "" && path == "/mcp-to-claude" {
					if err := os.WriteFile(filepath.Join(dir, tc.name+".html"), []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}
