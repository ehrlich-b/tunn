package host

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
	"gopkg.in/yaml.v3"
)

func agentKitHandler(cfg *config.Config) http.Handler {
	p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
	return p.createHandler()
}

func TestAgentKitRoutes(t *testing.T) {
	handler := agentKitHandler(&config.Config{Domain: "tunn.to"})
	for _, route := range []struct {
		path, contentType string
	}{
		{"/agents/prompt.md", "text/markdown; charset=utf-8"},
		{"/agents/skill/SKILL.md", "text/markdown; charset=utf-8"},
		{"/llms.txt", "text/plain; charset=utf-8"},
	} {
		t.Run(route.path, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(method, "https://tunn.to"+route.path, nil))
				if method != http.MethodGet && method != http.MethodHead {
					if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
						t.Fatalf("%s: status=%d headers=%v", method, w.Code, w.Header())
					}
					continue
				}
				if w.Code != http.StatusOK || w.Header().Get("Content-Type") != route.contentType {
					t.Fatalf("%s: status=%d headers=%v", method, w.Code, w.Header())
				}
				if method == http.MethodHead {
					if w.Body.Len() != 0 {
						t.Fatal("HEAD returned a body")
					}
					continue
				}
				body := strings.Join(strings.Fields(strings.ToLower(strings.ReplaceAll(w.Body.String(), "`", ""))), " ")
				for _, safety := range []string{"human approval of the device code", "never use --public by default", "--allow", "unlisted account", "403"} {
					if !strings.Contains(body, safety) {
						t.Errorf("missing safety guidance %q", safety)
					}
				}
				if strings.Contains(body, "<html") {
					t.Fatal("agent text was wrapped in HTML")
				}
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://offline.tunn.to"+route.path, nil))
			if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "# tunn") {
				t.Fatalf("documentation claimed a publisher route: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestAgentKitPrompt(t *testing.T) {
	w := httptest.NewRecorder()
	agentKitHandler(&config.Config{Domain: "tunn.to"}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://tunn.to/agents/prompt.md", nil))
	body := strings.Join(strings.Fields(w.Body.String()), " ")
	for _, want := range []string{"port PORT", "EMAILS", "https://tunn.to/install.sh", "tunn login", "verification URL, code and expiry", "wait for me", "tunn PORT --allow=EMAILS", "signed out", "owner or an allowed email", "unlisted account must receive 403", "pending", "Never print or commit credential files"} {
		if !strings.Contains(body, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	if len(strings.Fields(body)) > 350 {
		t.Fatal("prompt is too long to paste conveniently")
	}
}

func TestAgentKitPackagedSkill(t *testing.T) {
	w := httptest.NewRecorder()
	agentKitHandler(&config.Config{Domain: "tunn.to"}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://tunn.to/agents/skill/SKILL.md", nil))
	source, err := os.ReadFile("../../skills/tunn/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	if w.Body.String() != string(source) {
		t.Fatal("served skill differs from the packaged source")
	}
	parts := strings.SplitN(string(source), "---\n", 3)
	if len(parts) != 3 || parts[0] != "" {
		t.Fatal("missing YAML frontmatter")
	}
	var metadata struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal([]byte(parts[1]), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Name != "tunn" {
		t.Fatalf("skill name = %q", metadata.Name)
	}
	for _, trigger := range []string{"share a preview", "expose a port privately", "put a login on localhost"} {
		if !strings.Contains(strings.ToLower(metadata.Description), trigger) {
			t.Errorf("skill description missing trigger %q", trigger)
		}
	}
	for _, install := range []string{"Claude Code", "Codex", "Cursor", ".claude/skills/tunn", ".agents/skills/tunn", ".cursor/skills/tunn", "curl -fsSL https://tunn.to/agents/skill/SKILL.md -o", "tunn login", "If no person can approve, stop", "Never print or", "expect 403"} {
		if !strings.Contains(string(source), install) {
			t.Errorf("skill missing %q", install)
		}
	}
}

func TestAgentKitIndexUsesPricingSources(t *testing.T) {
	for _, cfg := range []*config.Config{
		{Domain: "tunn.to"},
		{Domain: "tunn.to", ProMonthlyUSD: 7, ProYearlyUSD: 70, OwnerMonthlyRequests: 1234, OwnerMonthlyBytes: 123456789},
		{Domain: "tunn.to", OwnerMonthlyRequests: 1500000},
	} {
		handler := agentKitHandler(cfg)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://tunn.to/llms.txt", nil))
		body := w.Body.String()
		d := (&ProxyServer{config: cfg}).revenueData()
		for _, want := range []string{
			fmt.Sprintf("Free: %d concurrent tunnels, Requests: unlimited (fair use), %s monthly metered transfer, %d reserved name.", d.FreeTunnels, d.FreeBytes, d.FreeReservations),
			fmt.Sprintf("Pro: $%d/month or $%d/year; %d concurrent tunnels, Requests: unlimited (fair use), %s monthly metered transfer, %d reserved names.", d.MonthlyUSD, d.YearlyUSD, d.ProTunnels, d.ProBytes, d.Reservations),
		} {
			if !strings.Contains(body, want) {
				t.Errorf("index disagrees with pricing data: missing %q", want)
			}
		}
		if allowance := regexp.MustCompile(`(?i)\b[0-9][0-9,]* (monthly admissions|requests)\b`).FindString(body); allowance != "" {
			t.Errorf("index advertises a numeric request allowance with abuse ceiling %d: %q", cfg.OwnerMonthlyRequests, allowance)
		}
		for _, page := range agentKitPages {
			if !strings.Contains(body, "https://tunn.to"+page.path) {
				t.Errorf("index missing served agent page %q", page.path)
			}
		}
		links := regexp.MustCompile(`\]\((https://tunn\.to[^)]+)\)`).FindAllStringSubmatch(body, -1)
		if len(links) < 7 {
			t.Fatal("index missing documentation links")
		}
		for _, link := range links {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, link[1], nil))
			if response.Code != http.StatusOK {
				t.Errorf("index links to unavailable page %s: %d", link[1], response.Code)
			}
		}
	}
}
