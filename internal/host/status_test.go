package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	statuspage "github.com/ehrlich-b/tunn/internal/status"
)

func statusRequest(p *ProxyServer, method, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://tunn.test"+path, nil)
	r.Header.Set("Authorization", "Bearer fixture-not-for-collector")
	r.Header.Set("Cookie", "fixture=value")
	r.Header.Set("Tunn-Authorization", "Bearer fixture-endpoint")
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}
func TestStatusRelayPublicRoutesAndDocs(t *testing.T) {
	p := securityProxy(securityDB(t))
	s, err := statuspage.Open(filepath.Join(t.TempDir(), "status.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Record(context.Background(), statuspage.Sample{CheckedAt: time.Now(), Health: true, Ready: true}); err != nil {
		t.Fatal(err)
	}
	handler := statuspage.Handler(s)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Tunn-Authorization") != "" || r.URL.RawQuery != "" {
			t.Error("forwarded visitor metadata")
		}
		handler.ServeHTTP(w, r)
	}))
	defer collector.Close()
	p.config.StatusURL = collector.URL
	for _, path := range []string{"/status", "/status.json"} {
		w := statusRequest(p, "GET", path+"?fixture=omit")
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code, w.Header())
		}
		if path == "/status" && !strings.Contains(w.Body.String(), iconHead) {
			t.Fatal("status page missing shared icons")
		}
		if path == "/status.json" {
			var v statuspage.Snapshot
			if err = json.Unmarshal(w.Body.Bytes(), &v); err != nil || v.State != "healthy" {
				t.Fatal(err, v)
			}
		}
		if w = statusRequest(p, "HEAD", path); w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal(w.Code, w.Body.Len())
		}
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			if w = statusRequest(p, method, path); w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
				t.Fatal(method, w.Code)
			}
		}
	}
	for _, path := range []string{"/docs/status", "/docs/docker"} {
		if w := statusRequest(p, "GET", path); w.Code != 200 || !strings.Contains(w.Body.String(), "<h1") {
			t.Fatal(path, w.Code)
		}
		if w := statusRequest(p, "HEAD", path); w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal(path, w.Code, w.Body.Len())
		}
		if w := statusRequest(p, "POST", path); w.Code != 405 {
			t.Fatal(path, w.Code)
		}
	}
	if w := statusRequest(p, "GET", "/docs/status/other"); w.Code != 404 {
		t.Fatal("invented docs", w.Code)
	}
	// Publisher origins must retain ownership of these paths, including private access.
	endpoint, _ := securityEndpoint(p, "demo", "", "", []string{"owner@example.com"}, false)
	for _, path := range []string{"/status", "/status.json", "/docs/status", "/docs/docker"} {
		r := httptest.NewRequest("GET", "https://demo.tunn.test"+path, nil)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code == 200 {
			t.Fatal("private publisher bypassed", path)
		}
		endpoint.AllowedEmails = nil
		w = httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 200 || w.Body.String() != "fixture" {
			t.Fatal("publisher path intercepted", path, w.Code, w.Body.String())
		}
		endpoint.AllowedEmails = []string{"owner@example.com"}
	}
	r := httptest.NewRequest("GET", "https://tunn.test:444/status", nil)
	w := httptest.NewRecorder()
	p.handleStatus(w, r)
	if w.Code != 403 {
		t.Fatal("wrong port accepted", w.Code)
	}
}
func TestStatusRelayFailuresRemainUnknown(t *testing.T) {
	p := securityProxy(securityDB(t))
	for _, origin := range []string{"not-an-origin", "http://127.0.0.1:1"} {
		p.config.StatusURL = origin
		w := statusRequest(p, "GET", "/status.json")
		var v statuspage.Snapshot
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || w.Code != 503 || v.State != "unknown" || v.Observed != 0 {
			t.Fatal(origin, w.Code, err, v)
		}
	}
	var hits int
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer destination.Close()
	for _, tc := range []struct {
		code        int
		contentType string
		body        string
	}{{302, "text/html; charset=utf-8", "redirect"}, {500, "text/html; charset=utf-8", "error"}, {200, "text/plain", "wrong media"}, {503, "application/json; charset=utf-8", `{"state":"unknown"}`}} {
		collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", destination.URL)
			w.Header().Set("Content-Type", tc.contentType)
			w.WriteHeader(tc.code)
			_, _ = w.Write([]byte(tc.body))
		}))
		p.config.StatusURL = collector.URL
		w := statusRequest(p, "GET", "/status.json")
		collector.Close()
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"state":"unknown"`) {
			t.Fatal(tc, w.Code, w.Body.String())
		}
	}
	if hits != 0 {
		t.Fatal("redirect followed")
	}
	// Read deadline must bound an upstream that never sends headers.
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer collector.Close()
	p.config.StatusURL = collector.URL
	started := time.Now()
	w := statusRequest(p, "GET", "/status.json")
	if w.Code != 503 || time.Since(started) > 5*time.Second {
		t.Fatal("collector deadline", w.Code, time.Since(started))
	}
}

func TestStatusUnknownSharedIcons(t *testing.T) {
	p := securityProxy(securityDB(t))
	p.config.StatusURL = "http://127.0.0.1:1"
	w := statusRequest(p, "GET", "/status")
	if w.Code != 503 || !strings.Contains(w.Body.String(), iconHead) {
		t.Fatal("unknown status must include shared icons")
	}
}

// TestStatusObserverImportProxy exercises the offline bridge through the actual
// relay proxy. The fixture is synthetic, and the service clock is never reset.
func TestStatusObserverImportProxy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "imported.db")
	command := exec.Command("python3", "../../scripts/status-observer/import_status.py", "--data-dir", "../../scripts/status-observer/testdata/synthetic", "--db", dbPath, "--synthetic", "--now", "2026-10-01T12:02:10Z")
	report, err := command.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(report))
	}
	t.Log("SYNTHETIC import report:", string(report))
	s, err := statuspage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now, _ := time.Parse(time.RFC3339, "2026-10-01T12:02:10Z")
	v, err := s.Snapshot(context.Background(), now)
	if err != nil || v.Observed != 2 || v.Healthy != 2 || v.State != "healthy" || v.Days[len(v.Days)-1].State != "partial" {
		t.Fatal("imported health/readiness history", v, err)
	}
	if v.Days[0].State != "unknown" || v.Days[0].Observed != 0 {
		t.Fatal("invented history", v.Days[0])
	}
	stale, err := s.Snapshot(context.Background(), now.Add(151*time.Second))
	if err != nil || stale.State != "unknown" || stale.Observed != 2 {
		t.Fatal("stale history", stale, err)
	}
	// Fixed fixture clock in the backend only, to render all historical states.
	// The operator's offline server always uses the current clock.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statuspage.Render(w, r, v, 200)
	}))
	defer backend.Close()
	p := securityProxy(securityDB(t))
	p.config.StatusURL = backend.URL
	for _, path := range []string{"/status", "/status.json"} {
		w := statusRequest(p, "GET", path)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
		if path == "/status.json" {
			var got statuspage.Snapshot
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Observed != 2 || got.Healthy != 2 || got.State != "healthy" {
				t.Fatal(got, err)
			}
		} else if !strings.Contains(w.Body.String(), "Synthetic fixture") || !strings.Contains(w.Body.String(), "partial") {
			t.Fatal("synthetic history missing", w.Body.String())
		}
		t.Logf("SYNTHETIC loopback proxy %s: HTTP %d; observed=2 healthy=2; home/download failures excluded", path, w.Code)
	}
	// Production-time rendering of a recorded fixture remains stale/unknown.
	actual := httptest.NewRecorder()
	statuspage.Handler(s).ServeHTTP(actual, httptest.NewRequest("GET", "/status.json", nil))
	var current statuspage.Snapshot
	if err := json.Unmarshal(actual.Body.Bytes(), &current); err != nil || current.State != "unknown" {
		t.Fatal(current, err)
	}
}

func TestStatusUnconfigured(t *testing.T) {
	p := securityProxy(securityDB(t))
	for _, path := range []string{"/status", "/status.json"} {
		w := statusRequest(p, "GET", path)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Public checks aren't published yet.") || (path == "/status" && !strings.Contains(w.Body.String(), "mailto:support@tunn.to")) {
			t.Fatalf("%s: %d %q", path, w.Code, w.Body.String())
		}
		w = statusRequest(p, "HEAD", path)
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Fatalf("HEAD %s: %d %q", path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/", "/docs", "/docs/status", "/pricing", "/login"} {
		w := statusRequest(p, "GET", path)
		if strings.Contains(w.Body.String(), `href="/status"`) {
			t.Fatalf("status link in %s", path)
		}
	}
	p.config.StatusURL = "http://127.0.0.1:1"
	if w := statusRequest(p, "GET", "/"); !strings.Contains(w.Body.String(), `href="/status"`) {
		t.Fatal("configured homepage missing link")
	}
}

// TestStatusScreens captures the real relay handlers using a local collector.
func TestStatusScreens(t *testing.T) {
	dir := os.Getenv("TUNN_STATUS_SCREENSHOTS")
	browser := os.Getenv("TUNN_STATUS_BROWSER")
	if dir == "" || browser == "" {
		t.Skip("set screenshot directory and browser")
	}
	p := securityProxy(securityDB(t))
	s, err := statuspage.Open(filepath.Join(t.TempDir(), "status.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Record(context.Background(), statuspage.Sample{CheckedAt: time.Now(), Health: true, Ready: true}); err != nil {
		t.Fatal(err)
	}
	collector := httptest.NewServer(statuspage.Handler(s))
	defer collector.Close()
	for _, configured := range []bool{false, true} {
		p.config.StatusURL = ""
		label := "unset"
		if configured {
			p.config.StatusURL = collector.URL
			label = "set"
		}
		handler := p.createHandler()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.Host = "tunn.test"; handler.ServeHTTP(w, r) }))
		for _, page := range []string{"home", "status"} {
			path := "/"
			if page == "status" {
				path = "/status"
			}
			for _, width := range []string{"390", "1440"} {
				file := filepath.Join(dir, label+"-"+page+"-"+width+".png")
				cmd := exec.Command(browser, "--headless", "--no-sandbox", "--disable-gpu", "--disable-background-networking", "--hide-scrollbars", "--window-size="+width+",900", "--screenshot="+file, server.URL+path)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("capture %s: %v %s", file, err, out)
				}
			}
		}
		server.Close()
	}
}

func TestStatusAccountLinks(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	for _, configured := range []bool{false, true} {
		f.p.config.StatusURL = ""
		if configured {
			f.p.config.StatusURL = "http://127.0.0.1:8091"
		}
		w := f.call("GET", "/account", nil, f.cookie, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), `href="/status"`) != configured {
			t.Fatalf("configured=%v status=%d", configured, w.Code)
		}
	}
}

func TestStatusDownloadPreservesBytes(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TUNN_DOWNLOAD_DIR", root)
	t.Setenv("TUNN_DOWNLOAD_BASE", "")
	body := []byte("\x7fELF\x00binary <a href=\"/status\">Status</a>\x00end")
	if err := os.Mkdir(filepath.Join(root, "v0.149.5"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "v0.149.5", "tunn-linux-amd64"), body, 0644); err != nil {
		t.Fatal(err)
	}
	p := securityProxy(securityDB(t))
	for _, configured := range []bool{false, true} {
		if configured {
			p.config.StatusURL = "http://127.0.0.1:8091"
		}
		w := statusRequest(p, "GET", "/dl/v0.149.5/tunn-linux-amd64")
		if w.Code != 200 || string(w.Body.Bytes()) != string(body) {
			t.Fatalf("configured=%v code=%d body=%q", configured, w.Code, w.Body.Bytes())
		}
	}
}

func TestStatusPublisherDenial(t *testing.T) {
	p := securityProxy(securityDB(t))
	securityEndpoint(p, "demo", "owner@example.com", "", []string{"owner@example.com"}, false)
	cookie := securityCookie(t, p, "other@example.com")
	for _, configured := range []bool{false, true} {
		if configured {
			p.config.StatusURL = "http://127.0.0.1:8091"
		}
		r := httptest.NewRequest("GET", "https://demo.tunn.test/", nil)
		r.Header.Set("Accept", "text/html")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 403 || strings.Contains(w.Body.String(), `href="https://tunn.test/status"`) != configured {
			t.Fatalf("configured=%v code=%d body=%s", configured, w.Code, w.Body.String())
		}
	}
}

func TestStatusWildcardDenial(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	cookie := appSessionCookie(t, p, "guest@example.com", "google", true, appHost)
	for _, configured := range []bool{false, true} {
		p.config.StatusURL = ""
		if configured {
			p.config.StatusURL = "http://127.0.0.1:8091"
		}
		r := httptest.NewRequest("GET", "https://"+appHost+"/", nil)
		r.Header.Set("Accept", "text/html")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `href="https://tunn.test/status"`) != configured {
			t.Fatalf("configured=%v code=%d body=%s", configured, w.Code, w.Body.String())
		}
	}
}
