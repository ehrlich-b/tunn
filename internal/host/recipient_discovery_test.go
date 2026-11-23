package host

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecipientDiscovery(t *testing.T) {
	const discovery = `Building something too? <a href="/docs" rel="noreferrer" referrerpolicy="no-referrer">Share your own local app.</a>`
	t.Run("private_login", func(t *testing.T) {
		p, _, _, _ := meteringRelay(t, false, "unused")
		p.config.GitHubClientID = "fixture"
		destination := "https://api.tunn.test/preview?token=secret&email=recipient@example.com"
		r := httptest.NewRequest("GET", destination, nil)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != http.StatusFound {
			t.Fatalf("private redirect: %d", w.Code)
		}
		login, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		claims, valid := p.parseDomainToken(login.Query().Get("request"), "domain_login_request")
		if !valid || login.Path != "/auth/domain" || claims["host"] != "api.tunn.test" || claims["path"] != "/preview?token=secret&email=recipient@example.com" {
			t.Fatal("signed handoff lost destination")
		}
		handoffURL := login.String()
		w = httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, httptest.NewRequest("GET", handoffURL, nil))
		if w.Code != http.StatusFound {
			t.Fatalf("handoff: %d", w.Code)
		}
		login, err = url.Parse(w.Header().Get("Location"))
		if err != nil || login.Query().Get("tunnel") != "api" || login.Query().Get("return_to") != handoffURL {
			t.Fatal("login did not retain signed handoff and tunnel label")
		}
		w = httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.test"+login.String(), nil))
		body := w.Body.String()
		if w.Code != 200 || strings.Count(body, discovery) != 1 {
			t.Fatalf("missing discovery: %d", w.Code)
		}
		primary := `/auth/github?return_to=` + url.QueryEscape(login.Query().Get("return_to"))
		if strings.Index(body, primary) < 0 || strings.Index(body, primary) > strings.Index(body, discovery) {
			t.Fatal("sign-in/return destination must remain first")
		}
		// The complete anchor is fixed: no source, hostname, token or identity can enter it.
		if strings.Contains(body, "shared-access") || strings.Contains(body, "sendBeacon") {
			t.Fatal("unexpected measurement")
		}
		if dir := os.Getenv("TUNN_RECIPIENT_FIXTURES"); dir != "" {
			if err := os.WriteFile(filepath.Join(dir, "access.html"), w.Body.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
		for _, tunnel := range []string{"", `<script>alert("recipient@example.com")</script>`} {
			w = httptest.NewRecorder()
			p.handleLogin(w, httptest.NewRequest("GET", "https://tunn.test/auth/login?"+url.Values{"tunnel": {tunnel}}.Encode(), nil))
			body = w.Body.String()
			if strings.Contains(body, tunnel) && tunnel != "" {
				t.Fatal("unescaped tunnel text")
			}
			if (tunnel != "") != strings.Contains(body, discovery) {
				t.Fatal("discovery must only appear for private access")
			}
			if tunnel != "" && !strings.Contains(body, "&lt;script&gt;") {
				t.Fatal("escaped label missing")
			}
		}
	})
	for _, tc := range []struct {
		name, method, path, body string
		public                   bool
	}{
		{"app", "GET", "/preview", "<html><body>Original app & data</body></html>", false},
		{"webhook", "POST", "/webhook", "{\"event\":\"original\"}\n", true},
		{"mcp", "POST", "/mcp", "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, tunnel, _, _ := meteringRelay(t, false, tc.body)
			if tc.public {
				tunnel.AllowedEmails = nil
			}
			r := httptest.NewRequest(tc.method, "https://api.tunn.test"+tc.path, strings.NewReader("fixture request"))
			if !tc.public {
				r.Header.Set("Authorization", "Bearer "+relayJWT(t, p, "owner@example.com"))
			}
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, r)
			if w.Code != 200 || w.Body.String() != tc.body {
				t.Fatalf("upstream bytes changed: %d %q", w.Code, w.Body.String())
			}
		})
	}
}
