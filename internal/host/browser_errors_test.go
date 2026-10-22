package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
)

// Production handlers and assets rendered in an isolated browser, without a
// hosted account or external identity provider.
func TestBrowserErrorScreenshots(t *testing.T) {
	module, evidence := os.Getenv("TUNN_ERRORS_PLAYWRIGHT_MODULE"), os.Getenv("TUNN_ERRORS_EVIDENCE")
	if module == "" || evidence == "" {
		t.Skip("set TUNN_ERRORS_PLAYWRIGHT_MODULE and TUNN_ERRORS_EVIDENCE for browser acceptance")
	}
	f := newWebInspectorFixture(t, 0, 0)
	p := f.p
	p.config.GoogleClientID, p.config.GoogleClientSecret = "fixture", "fixture"
	expired, err := p.storage.CreateDeviceCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec("UPDATE device_codes SET expires_at=? WHERE code=?", time.Now().Add(-time.Minute).Unix(), expired.Code); err != nil {
		t.Fatal(err)
	}
	type snapshot struct {
		Name, URL, HTML string
		Status          int
	}
	var pages []snapshot
	add := func(name, target string, w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status {
			t.Fatalf("%s: status %d, want %d: %s", name, w.Code, status, w.Body)
		}
		pages = append(pages, snapshot{name, target, w.Body.String(), w.Code})
	}
	request := func(target string, cookie *http.Cookie) *http.Request {
		r := httptest.NewRequest("GET", target, nil)
		r.Header.Set("Accept", "text/html")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		return r
	}
	for _, item := range []struct {
		name, path string
		status     int
	}{
		{"not-found", "/missing-page", 404},
		{"auth-error", "/auth/google/callback?state=invalid&code=interrupted", 400},
		{"device-expired", "/login?code=" + expired.UserCode, 400},
	} {
		target := "https://tunn.test" + item.path
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, request(target, nil))
		add(item.name, target, w, item.status)
	}
	code, err := p.storage.CreateDeviceCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := p.storage.AuthorizeDeviceCode(context.Background(), code.Code, "owner@example.com"); err != nil || !ok {
		t.Fatal("authorize fixture", err)
	}
	target := "https://tunn.test/login?code=" + code.UserCode
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, request(target, nil))
	add("device-used", target, w, 400)
	target = "https://api.tunn.test/checkout"
	w = httptest.NewRecorder()
	p.writeLocalAppDown(w, request(target, f.cookie))
	add("app-down", target, w, 502)
	w = httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, request(target, f.accountCookie(t, "visitor@example.com")))
	add("access-denied", target, w, 403)
	ip, _, _, _ := webSharingFixture(t)
	setHostPolicy(t, ip, "api", []string{"192.0.2.0/24"}, nil)
	w = policyOpen(ip, "198.51.100.9:443", "", "anonymous", map[string]string{"Accept": "text/html"})
	add("ip-blocked", "https://api.tunn.test/", w, 403)
	delete(p.tunnelServer.tunnels, "api")
	for _, count := range []int{0, 1, 8, storage.FreeTunnelLimit} {
		for name := range p.tunnelServer.tunnels {
			delete(p.tunnelServer.tunnels, name)
		}
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("regional-background-worker-%02d", i+1)
			p.tunnelServer.tunnels[name] = &TunnelConnection{TunnelID: name, AccountID: f.tunnel.AccountID, TargetURL: "http", Connected: time.Now().Add(-2 * time.Hour)}
		}
		w := f.call("GET", "/account", nil, f.cookie, nil)
		name := fmt.Sprintf("account-%d", count)
		if count == storage.FreeTunnelLimit {
			name = "account-plan-limit"
		}
		add(name, "https://tunn.test/account", w, 200)
	}
	assets := map[string][]byte{}
	entries, err := os.ReadDir("templates/assets")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := "/assets/" + entry.Name()
		w := httptest.NewRecorder()
		if serveWebAsset(w, httptest.NewRequest("GET", path, nil)) && w.Code == 200 {
			assets[path] = w.Body.Bytes()
		}
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"pages": pages, "assets": assets})
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(evidence, "fixtures.json")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../scripts/integration-tests/browser-errors.cjs", input, evidence)
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
}

func TestBrowserErrorRecoveryRoutes(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	p := f.p
	p.config.GoogleClientID, p.config.GoogleClientSecret = "fixture", "fixture"
	for _, signedIn := range []bool{false, true} {
		r := httptest.NewRequest("GET", "https://tunn.test/missing?secret=DO_NOT_REFLECT", nil)
		r.Header.Set("Accept", "text/html")
		want := `href="/">Go home</a>`
		if signedIn {
			r.AddCookie(f.cookie)
			want = `href="/account">Go to account</a>`
		}
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 404 || !strings.Contains(w.Body.String(), want) || strings.Contains(w.Body.String(), "DO_NOT_REFLECT") {
			t.Fatalf("404 recovery (signed in %v): %d %s", signedIn, w.Code, w.Body)
		}
		path := "/"
		if signedIn {
			path = "/account"
		}
		r.URL.Path, r.URL.RawQuery = path, ""
		w = httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("404 recovery target %s: %d", path, w.Code)
		}
	}
	for _, item := range []struct {
		path, body string
		status     int
	}{
		{"/missing", "404 page not found\n", 404},
		{"/auth/google/callback?state=invalid&code=invalid", "Invalid Google login state\n", 400},
	} {
		r := httptest.NewRequest("GET", "https://tunn.test"+item.path, nil)
		r.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != item.status || w.Body.String() != item.body {
			t.Fatalf("machine response changed: %d %s", w.Code, w.Body)
		}
	}
	for _, message := range []string{"Invalid Google login state", "Invalid login state", "Missing Google login binding", "Invalid Google login binding", "Missing Google authorization"} {
		r := httptest.NewRequest("GET", "https://tunn.test/auth/google/callback", nil)
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		writeBrowserAuthError(w, r, message, 400, "technical diagnosis", "")
		if w.Code != 400 || !strings.Contains(w.Body.String(), "Sign-in expired or interrupted") || strings.Contains(w.Body.String(), "technical diagnosis") {
			t.Fatalf("browser sign-in explanation: %s", w.Body)
		}
	}
}
