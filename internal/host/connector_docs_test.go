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
	t.Setenv("TUNN_MCP_VERIFIED", "")
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
	const account = "You need an account that supports custom MCP connectors."
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
	for _, tc := range []struct {
		name, value string
		clients     []string
		more        int
	}{
		{"unset", "", nil, 0},
		{"whitespace", " \t\n\r\u2003", nil, 0},
		{"one", longClients[0], longClients[:1], 0},
		{"multiple", strings.Join(longClients[:2], "; "), longClients[:2], 0},
		{"limit", strings.Join(longClients[:4], "; "), longClients[:4], 0},
		{"empty_entries", " ; " + longClients[0] + "; ; ", longClients[:1], 0},
		{"separators", "; ;", []string{"; ;"}, 0},
		{"escaped", `<script>alert("client")</script> & <img src=x onerror=alert(1)> {{.MCPVerified}}`, []string{`<script>alert("client")</script> & <img src=x onerror=alert(1)> {{.MCPVerified}}`}, 0},
		{"template_expression", `Example client {{.MonthlyUSD}}`, []string{`Example client {{.MonthlyUSD}}`}, 0},
		{"long", strings.Join(longClients, "; "), longClients[:4], 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TUNN_MCP_VERIFIED", tc.value)
			cfg := &config.Config{Domain: "tunn.to"}
			p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
			handler := p.createHandler()
			for _, path := range []string{"/", "/mcp-to-claude", "/docs/mcp-to-claude"} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to"+path, nil))
				if w.Code != 200 {
					t.Fatalf("%s: status %d", path, w.Code)
				}
				body := w.Body.String()
				value := strings.TrimSpace(tc.value)
				if !strings.Contains(body, account) {
					t.Errorf("%s: missing account requirement", path)
				}
				if value == "" {
					if !strings.Contains(body, `<p class="note">`+experimental+" "+account+"</p>") {
						t.Errorf("%s: original Experimental note changed", path)
					}
				} else {
					start := strings.Index(body, `<div class="note mcp-verification">`)
					if start < 0 {
						t.Fatalf("%s: missing verification note", path)
					}
					note := strings.SplitN(body[start:], "</div>", 2)[0]
					if !strings.Contains(note, "Verified with:") || strings.Count(note, "<li ") != len(tc.clients) {
						t.Errorf("%s: wrong visible clients: %s", path, note)
					}
					for _, client := range tc.clients {
						if !strings.Contains(note, html.EscapeString(client)) {
							t.Errorf("%s: missing escaped client %q", path, client)
						}
					}
					if strings.Contains(note, "+4 more") != (tc.more == 4) || strings.Contains(note, "+0 more") {
						t.Errorf("%s: wrong overflow count: %s", path, note)
					}
					if tc.more > 0 && strings.Contains(note, longClients[4]) {
						t.Errorf("%s: hidden client rendered", path)
					}
					if strings.Contains(note, "<script>") || strings.Contains(note, "<img ") {
						t.Errorf("%s: unescaped client HTML", path)
					}
				}
				if value == "" && strings.Contains(body, "Verified with:") || value != "" && strings.Contains(body, experimental) {
					t.Errorf("%s: wrong verification state", path)
				}
				if dir := os.Getenv("TUNN_MCP_PREVIEW_DIR"); dir != "" && path == "/mcp-to-claude" {
					if err := os.WriteFile(filepath.Join(dir, tc.name+".html"), []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if dir := os.Getenv("TUNN_MCP_PREVIEW_DIR"); dir != "" && path == "/" {
					if err := os.WriteFile(filepath.Join(dir, "homepage-"+tc.name+".html"), []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestMCPToClaudeVerifiedOtherTemplates(t *testing.T) {
	t.Setenv("TUNN_MCP_VERIFIED", "")
	before := withSiteChrome(shareDevServerOAuthHTML)
	t.Setenv("TUNN_MCP_VERIFIED", "Example <client> 2026-11-12")
	if got := withSiteChrome(shareDevServerOAuthHTML); got != before {
		t.Fatal("verification fact changed another guide")
	}
}
