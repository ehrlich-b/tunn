package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	for _, origin := range []string{"", "not-an-origin", "http://127.0.0.1:1"} {
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
