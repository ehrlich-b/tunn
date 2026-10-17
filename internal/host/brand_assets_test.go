package host

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
)

func TestBrandIconDelivery(t *testing.T) {
	for _, name := range []string{"/favicon.ico", "/assets/favicon.svg", "/assets/apple-touch-icon.png", "/assets/icon-192.png", "/assets/icon-512.png", "/assets/site.webmanifest"} {
		t.Run(name, func(t *testing.T) {
			get := httptest.NewRecorder()
			if !serveWebAsset(get, httptest.NewRequest("GET", name, nil)) || get.Code != 200 || get.Body.Len() == 0 {
				t.Fatalf("GET %s: %d", name, get.Code)
			}
			if get.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing nosniff")
			}
			head := httptest.NewRecorder()
			serveWebAsset(head, httptest.NewRequest("HEAD", name, nil))
			if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Type") != get.Header().Get("Content-Type") {
				t.Fatal("HEAD differs from GET")
			}
			post := httptest.NewRecorder()
			serveWebAsset(post, httptest.NewRequest("POST", name, nil))
			if post.Code != 405 || post.Header().Get("Allow") != "GET, HEAD" {
				t.Fatal("POST accepted")
			}
			if strings.HasSuffix(name, ".png") {
				cfg, err := png.DecodeConfig(bytes.NewReader(get.Body.Bytes()))
				want := map[string]int{"/assets/apple-touch-icon.png": 180, "/assets/icon-192.png": 192, "/assets/icon-512.png": 512}[name]
				if err != nil || cfg.Width != want || cfg.Height != want {
					t.Fatalf("invalid PNG dimensions: %+v %v", cfg, err)
				}
			}
			if name == "/favicon.ico" {
				b := get.Body.Bytes()
				if len(b) < 54 || binary.LittleEndian.Uint16(b[2:4]) != 1 || binary.LittleEndian.Uint16(b[4:6]) != 3 {
					t.Fatal("invalid ICO directory")
				}
				for i, want := range []byte{16, 32, 48} {
					if b[6+i*16] != want || b[7+i*16] != want {
						t.Fatal("missing ICO size")
					}
				}
			}
			if strings.HasSuffix(name, ".webmanifest") {
				var manifest struct{ Icons []struct{ Src string } }
				if err := json.Unmarshal(get.Body.Bytes(), &manifest); err != nil || len(manifest.Icons) != 2 {
					t.Fatal("invalid manifest")
				}
				for _, icon := range manifest.Icons {
					w := httptest.NewRecorder()
					if !serveWebAsset(w, httptest.NewRequest("GET", icon.Src, nil)) || w.Code != 200 {
						t.Fatal("broken manifest icon")
					}
				}
			}
		})
	}
}

func TestBrowserAuthRecovery(t *testing.T) {
	p := &ProxyServer{config: &config.Config{Domain: "tunn.test", PublicAddr: "tunn.test:443", GoogleClientID: "test", GoogleClientSecret: "test"}}
	r := httptest.NewRequest("GET", "https://tunn.test/auth/google/callback?state=bad&code=bad", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	p.handleGoogleCallback(w, r)
	if w.Code != 400 {
		t.Fatalf("callback status = %d", w.Code)
	}
	for _, want := range []string{"Invalid Google login state", `class="site-header"`, `class="site-footer"`, `href="/auth/login"`, `href="/favicon.ico"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
	r = httptest.NewRequest("GET", "https://private.example.test/report", nil)
	r.Header.Set("Accept", "text/html")
	w = httptest.NewRecorder()
	p.writeAuthError(w, r, "Forbidden", 403, "Ask the owner for access.")
	if w.Code != 403 || !strings.Contains(w.Body.String(), `href="https://tunn.test:443/auth/login"`) || !strings.Contains(w.Body.String(), `href="https://tunn.test:443/favicon.ico"`) {
		t.Fatal("app recovery must use the login authority")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("auth response can be cached")
	}
	r.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	p.writeAuthError(w, r, "Forbidden", http.StatusForbidden, "Ask the owner.")
	if w.Code != 403 || w.Body.String() != "Forbidden\n" {
		t.Fatal("machine error response changed")
	}
}
