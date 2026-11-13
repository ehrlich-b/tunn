package host

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
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
			fmt.Sprintf("| Free | $0 | %d | %s | unlimited (fair use) | %d |", d.FreeTunnels, d.FreeBytesShort, d.FreeReservations),
			fmt.Sprintf("| Pro | $%d/month or $%d/year | %d | %s | unlimited (fair use) | %d |", d.MonthlyUSD, d.YearlyUSD, d.ProTunnels, d.ProBytesShort, d.Reservations),
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
	for _, state := range []struct {
		name            string
		monthly, yearly bool
	}{
		{"closed", false, false},
		{"manual", true, true},
		{"automatic", true, true},
		{"monthly-only", true, false},
		{"yearly-only", false, true},
		{"missing-authority", false, false},
	} {
		t.Run(state.name, func(t *testing.T) {
			db, p, local, account := reviewRevenueFixture(t)
			p.config.StripeCheckoutURLYearly = "https://buy.stripe.com/fixture_year"
			switch state.name {
			case "closed":
				p.config.BillingEnabled = false
			case "automatic":
				p.config.StripeSecretKey = "sk_test_fixtureautomatic"
				p.config.StripeProPriceIDs = []string{"price_fixtureMonth123", "price_fixtureYear456"}
			case "monthly-only":
				p.config.StripeCheckoutURLYearly = ""
			case "yearly-only":
				p.config.StripeCheckoutURLMonthly = ""
			case "missing-authority":
				// A payment URL alone cannot authorize signed billing receipts.
				p.config.StripeWebhookSecret = ""
			}
			// Fail locally if a public read tries to contact a payment provider.
			var networkCalls atomic.Int32
			transport := http.DefaultTransport
			http.DefaultTransport = agentKitNoNetwork{calls: &networkCalls}
			t.Cleanup(func() { http.DefaultTransport = transport })
			assertAgentKitCheckoutAvailability(t, p.createHandler(), state.monthly, state.yearly)
			// Signed-in reads are still informational and must not prepare checkout.
			for _, path := range []string{"/llms.txt", "/pricing"} {
				w := revenueRequest(t, p, path, true)
				if w.Code != http.StatusOK || w.Header().Get("Location") != "" {
					t.Fatalf("public GET redirected to checkout: %s %d %v", path, w.Code, w.Header())
				}
			}
			var intents int
			if err := db.QueryRow(`SELECT count(*) FROM ops_checkout_intents`).Scan(&intents); err != nil {
				t.Fatal(err)
			}
			current, err := local.GetAccount(context.Background(), account.ID)
			if err != nil || current == nil {
				t.Fatal("reading fixture account", err)
			}
			if intents != 0 || current.Plan != "free" || current.BillingState != "available" || networkCalls.Load() != 0 {
				t.Fatalf("public GET changed billing: intents=%d plan=%s state=%s network=%d", intents, current.Plan, current.BillingState, networkCalls.Load())
			}
		})
	}
}

type agentKitNoNetwork struct{ calls *atomic.Int32 }

func (n agentKitNoNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	n.calls.Add(1)
	return nil, fmt.Errorf("unexpected network request to %s", r.URL.Host)
}

func assertAgentKitCheckoutAvailability(t *testing.T, handler http.Handler, monthly, yearly bool) {
	t.Helper()
	status := func(available bool) string {
		if available {
			return "available"
		}
		return "closed"
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://tunn.to/llms.txt", nil))
	want := fmt.Sprintf("Pro checkout: monthly %s; yearly %s.", status(monthly), status(yearly))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" || w.Header().Get("Location") != "" {
		t.Fatalf("index response: %d %v", w.Code, w.Header())
	}
	if strings.Count(w.Body.String(), "Pro checkout:") != 1 || !strings.Contains(w.Body.String(), "\n"+want+"\n") {
		t.Errorf("index checkout availability: want exactly one line %q", want)
	}
	if strings.Contains(w.Body.String(), "buy.stripe.com") {
		t.Error("index exposed a payment link")
	}
	pricing := httptest.NewRecorder()
	handler.ServeHTTP(pricing, httptest.NewRequest(http.MethodGet, "https://tunn.to/pricing", nil))
	if pricing.Code != http.StatusOK || pricing.Header().Get("Location") != "" {
		t.Fatalf("pricing response: %d %v", pricing.Code, pricing.Header())
	}
	for period, available := range map[string]bool{"monthly": monthly, "yearly": yearly} {
		if offered := strings.Contains(pricing.Body.String(), `href="/upgrade?period=`+period+`"`); offered != available {
			t.Errorf("index and pricing disagree about %s checkout", period)
		}
	}
}
