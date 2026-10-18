package host

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
)

func TestAgentsMarkdownRoutes(t *testing.T) {
	cfg := &config.Config{Domain: "tunn.to"}
	p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
	handler := p.createHandler()
	for path, body := range map[string]string{"/agents": agentsMarkdown, "/agents/SKILLS.md": agentsSkillsMarkdown} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
			t.Run(path+"/"+method, func(t *testing.T) {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(method, "https://tunn.to"+path, nil))
				if method == http.MethodPost {
					if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
						t.Fatalf("POST: %d %v", w.Code, w.Header())
					}
					return
				}
				if w.Code != 200 || w.Header().Get("Content-Type") != "text/markdown; charset=utf-8" {
					t.Fatalf("response: %d %v", w.Code, w.Header())
				}
				if method == http.MethodHead {
					if w.Body.Len() != 0 {
						t.Fatal("HEAD body")
					}
					return
				}
				if w.Body.String() != body || strings.Contains(w.Body.String(), "<html") {
					t.Fatal("markdown was wrapped or altered")
				}
			})
		}
		// Documentation routes must not claim a publisher's URL space.
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://offline.tunn.to"+path, nil))
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "# tunn") {
			t.Fatalf("publisher route: %d", w.Code)
		}
	}
}
