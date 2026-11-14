package host

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
)

func TestHomepageQuickstartFacts(t *testing.T) {
	t.Setenv("TUNN_MCP_VERIFIED", "")
	cfg := &config.Config{Domain: "tunn.to"}
	p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
	handler := p.createHandler()
	for _, tc := range []struct {
		path, file string
		facts      []string
	}{
		{"/", "homepage.html", []string{
			"Give a local HTTP app", "an HTTPS URL.", "outbound connection to the relay",
			"Keep both your app and the publisher running and connected.",
			"TLS ends at the tunn relay, which can read traffic.", "private to their owner",
			"tunn 3000 --public", "have not yet been verified end to end",
			"serializes calls through one child", "below 25 seconds",
		}},
		{"/docs", "quickstart.html", []string{
			"Browsers without a session go to sign-in.",
			"A signed-in account with a disallowed email gets a 403 at the edge, before anything reaches your app.",
		}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to"+tc.path, nil))
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			body := w.Body.String()
			for _, fact := range tc.facts {
				if !strings.Contains(body, fact) {
					t.Errorf("missing fact %q", fact)
				}
			}
			if strings.Contains(body, "Share anything") || strings.Contains(body, "Everyone else gets a 403") {
				t.Error("obsolete promise rendered")
			}
			if tc.path == "/" && strings.Index(body, "outbound connection to the relay") > strings.Index(body, "curl -fsSL") {
				t.Error("relay explanation follows installation")
			}
			if dir := os.Getenv("TUNN_FRONTPAGE_PREVIEW_DIR"); dir != "" {
				if err := os.WriteFile(filepath.Join(dir, tc.file), w.Body.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	if dir := os.Getenv("TUNN_FRONTPAGE_PREVIEW_DIR"); dir != "" {
		for _, asset := range []string{"system.css", "home.css", "ui.js"} {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to/assets/"+asset, nil))
			if w.Code != 200 {
				t.Fatalf("asset %s: status %d", asset, w.Code)
			}
			if err := os.MkdirAll(filepath.Join(dir, "assets"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "assets", asset), w.Body.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
