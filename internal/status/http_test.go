package status

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStatusOriginValidation(t *testing.T) {
	for _, raw := range []string{"https://relay.example", "https://relay.example/", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if _, err := Origin(raw); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{"", "//relay.example", "ftp://relay.example", "https://user:pass@relay.example", "https://relay.example/status", "https://relay.example?x=y", "https://relay.example?", "https://relay.example#x", "https://relay.example/%2f", "https://"} {
		if _, err := Origin(raw); err == nil {
			t.Fatal("invalid origin accepted", raw)
		}
	}
}
func TestStatusCollectorSuccessFailureRedirectAndTLS(t *testing.T) {
	var health, ready atomic.Int32
	health.Store(200)
	ready.Store(200)
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.URL.RawQuery != "" {
			t.Error("probe leaked metadata")
		}
		code := int(health.Load())
		if r.URL.Path == "/readyz" {
			code = int(ready.Load())
		} else if r.URL.Path != "/healthz" {
			t.Error(r.URL.Path)
		}
		if code == 302 {
			w.Header().Set("Location", destination.URL)
		}
		w.WriteHeader(code)
	}))
	defer probe.Close()
	s := statusStore(t)
	origin, _ := Origin(probe.URL)
	c := Collector{s, origin, ProbeClient(time.Second)}
	now := time.Now().UTC().Truncate(time.Minute)
	for _, tc := range []struct {
		h, r int
		want string
	}{{200, 200, "healthy"}, {200, 503, "degraded"}, {500, 200, "down"}, {302, 200, "down"}, {204, 200, "down"}, {200, 200, "healthy"}} {
		health.Store(int32(tc.h))
		ready.Store(int32(tc.r))
		now = now.Add(time.Minute)
		if err := c.Collect(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		if v := statusSnapshot(t, s, now); v.State != tc.want {
			t.Fatal(v.State, tc.want)
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("followed probe redirect")
	}
	tlsProbe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	c.Origin, _ = Origin(tlsProbe.URL)
	now = now.Add(time.Minute)
	if err := c.Collect(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if v := statusSnapshot(t, s, now); v.State != "down" {
		t.Fatal("untrusted TLS accepted")
	}
	tlsProbe.Close()
	now = now.Add(time.Minute)
	if err := c.Collect(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if v := statusSnapshot(t, s, now); v.State != "down" {
		t.Fatal("unreachable probe accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Collect(ctx, now.Add(time.Minute)); err == nil {
		t.Fatal("canceled probe recorded")
	}
}
func TestStatusCollectorTimeoutAndRunCancellation(t *testing.T) {
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer probe.Close()
	s := statusStore(t)
	origin, _ := Origin(probe.URL)
	c := Collector{s, origin, ProbeClient(20 * time.Millisecond)}
	now := time.Now().UTC()
	if err := c.Collect(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if v := statusSnapshot(t, s, now); v.State != "down" {
		t.Fatal("timeout green")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("collector did not stop")
	}
}
func TestStatusHTTPMethodsJSONEscapingAndUnavailable(t *testing.T) {
	s := statusStore(t)
	now := time.Now().UTC()
	recordStatus(t, s, now, true, true)
	if _, err := s.AddIncident(context.Background(), now, "<script>alert(1)</script>", "<b>plain text</b>"); err != nil {
		t.Fatal(err)
	}
	handler := Handler(s)
	for _, path := range []string{"/status", "/status.json"} {
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE"} {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(method, path, nil))
			want := 200
			if method != "GET" && method != "HEAD" {
				want = 405
			}
			if w.Code != want || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Security-Policy") == "" {
				t.Fatal(path, method, w.Code, w.Header())
			}
			if method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD body")
			}
			if method == "GET" && path == "/status.json" {
				var v Snapshot
				if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || v.State != "healthy" || len(v.Days) != 90 {
					t.Fatal(v, err)
				}
			}
			if method == "GET" && path == "/status" && (!strings.Contains(w.Body.String(), "&lt;script&gt;") || strings.Contains(w.Body.String(), "<script>")) {
				t.Fatal("incident HTML not escaped")
			}
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/status/other", nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	_ = s.Close()
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/status.json", nil))
	var v Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || w.Code != 503 || v.State != "unknown" {
		t.Fatal(w.Code, v, err)
	}
}
