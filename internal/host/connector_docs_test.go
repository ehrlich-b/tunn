package host

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
)

func TestConnectorGuideRoutes(t *testing.T) {
	cfg := &config.Config{Domain: "tunn.to", StatusURL: "http://127.0.0.1:8091"}
	p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
	handler := p.createHandler()
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
			if w.Body.String() != withSiteChrome(mcpToClaudeHTML) {
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
