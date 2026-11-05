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

func TestBuyerTrustPage(t *testing.T) {
	for _, tc := range []struct{ name, operating, merchant, window, status string }{
		{name: "missing"},
		{name: "partial", operating: "Example confirmed operating name for local preview"},
		{name: "whitespace", operating: " \t", merchant: "\n", window: " "},
		{name: "configured", operating: "Example operating name supplied for local preview", merchant: "Example merchant display supplied for local preview", window: "Daily 09:00–10:00 America/New_York (preview fixture only)"},
		{name: "html", operating: `<script>alert("operator")</script>`, merchant: `<img src=x onerror=alert(1)>`, window: `<b>weekdays & weekends</b>`},
		{name: "published", status: "http://127.0.0.1:8091"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Domain: "tunn.to", OperatingName: tc.operating, MerchantDisplayName: tc.merchant, SupportWindow: tc.window, StatusURL: tc.status}
			p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
			handler := p.createHandler()
			get := func(path string) string {
				t.Helper()
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to"+path, nil))
				if w.Code != 200 {
					t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
				}
				return w.Body.String()
			}
			body := get("/about")
			for _, want := range []string{"Bryan Ehrlich", "relay terminates TLS", "can read HTTP traffic", "local app and tunn publisher must stay running", "https://gitlab.com/ehrlich-b/tunn", "https://gitlab.com/ehrlich-b/tunn/-/releases", `href="mailto:support@tunn.to"`, `href="mailto:abuse@tunn.to"`, `href="/privacy"`, `href="/terms"`, "There is no uptime guarantee."} {
				if !strings.Contains(body, want) {
					t.Errorf("missing %q", want)
				}
			}
			for _, value := range []string{tc.operating, tc.merchant, tc.window} {
				expected := html.EscapeString(value)
				if strings.TrimSpace(value) == "" {
					expected = "Being confirmed; not currently available."
				}
				if !strings.Contains(body, "<dd>"+expected+"</dd>") {
					t.Errorf("fact not escaped or fallback missing: %q", value)
				}
			}
			for _, bad := range []string{`href="/report"`, "99.9%", "100% uptime", "SOC 2", "ISO 27001", "automatically activated", "instant activation", "<script>alert", "<img src=x", "<b>weekdays"} {
				if strings.Contains(body, bad) {
					t.Errorf("unsupported assertion or raw HTML %q", bad)
				}
			}
			if tc.status == "" {
				if !strings.Contains(body, "Public checks aren't published yet. Status history is unpublished.") {
					t.Error("missing unpublished status")
				}
				if strings.Contains(body, `href="/status"`) {
					t.Error("unconfigured status discovery")
				}
				if !strings.Contains(get("/status"), "Public checks aren't published yet.") {
					t.Error("status fallback differs")
				}
			} else if !strings.Contains(body, `href="/status"`) {
				t.Error("published status undiscoverable")
			}
			for _, path := range []string{"/", "/pricing", "/privacy", "/terms"} {
				page := get(path)
				footer := strings.Index(page, `<footer class="site-footer">`)
				if footer < 0 || !strings.Contains(page[footer:], `href="/about"`) {
					t.Errorf("%s missing footer discovery", path)
				}
				if path == "/pricing" && !strings.Contains(page, "Operator facts and support") {
					t.Error("pricing help link missing")
				}
			}
			for _, method := range []string{"HEAD", "POST"} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(method, "https://tunn.to/about", nil))
				if method == "HEAD" && (w.Code != 200 || w.Body.Len() != 0) {
					t.Error("HEAD response")
				}
				if method == "POST" && w.Code != 405 {
					t.Error("POST accepted")
				}
			}
			if dir := os.Getenv("TUNN_BUYER_PREVIEW_DIR"); dir != "" && (tc.name == "missing" || tc.name == "configured" || tc.name == "partial") {
				if err := os.WriteFile(filepath.Join(dir, tc.name+".html"), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
