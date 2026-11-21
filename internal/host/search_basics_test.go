package host

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
	"golang.org/x/net/html"
)

func searchPage(t *testing.T, handler http.Handler, path string) (string, *html.Node) {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://tunn.to"+path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d", path, w.Code)
	}
	doc, err := html.Parse(strings.NewReader(w.Body.String()))
	if err != nil {
		t.Fatal(err)
	}
	return w.Body.String(), doc
}

func searchNodes(n *html.Node, match func(*html.Node) bool) (nodes []*html.Node) {
	if match(n) {
		nodes = append(nodes, n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		nodes = append(nodes, searchNodes(c, match)...)
	}
	return
}

func searchAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func searchText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var s strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		s.WriteString(searchText(c))
	}
	return s.String()
}

func TestSearchMetadata(t *testing.T) {
	handler := agentKitHandler(&config.Config{Domain: "tunn.to"})
	for _, path := range []string{"/pricing", "/docs", "/docs/", "/about"} {
		t.Run(path, func(t *testing.T) {
			_, doc := searchPage(t, handler, path)
			heads := searchNodes(doc, func(n *html.Node) bool { return n.Type == html.ElementNode && n.Data == "head" })
			if len(heads) != 1 {
				t.Fatalf("head count %d", len(heads))
			}
			meta := map[string][]string{}
			for _, n := range searchNodes(heads[0], func(n *html.Node) bool { return n.Data == "meta" || n.Data == "link" }) {
				if n.Data == "meta" {
					meta[searchAttr(n, "name")+searchAttr(n, "property")] = append(meta[searchAttr(n, "name")+searchAttr(n, "property")], searchAttr(n, "content"))
				}
				if n.Data == "link" {
					meta[searchAttr(n, "rel")] = append(meta[searchAttr(n, "rel")], searchAttr(n, "href"))
				}
			}
			for _, key := range []string{"description", "canonical", "og:title", "og:description", "og:type", "og:site_name", "og:url"} {
				if len(meta[key]) != 1 || strings.TrimSpace(meta[key][0]) == "" {
					t.Fatalf("%s: %v", key, meta[key])
				}
			}
			canonical := "https://tunn.to" + strings.TrimSuffix(path, "/")
			for _, key := range []string{"canonical", "og:url"} {
				if meta[key][0] != canonical {
					t.Errorf("%s = %q", key, meta[key][0])
				}
			}
		})
	}
}

func TestSearchPricesAndLLMs(t *testing.T) {
	for _, prices := range [][2]int{{7, 70}, {13, 125}} {
		for _, availability := range []string{"both", "monthly", "yearly", "disabled", "missing-authority", "unsafe", "automatic"} {
			t.Run(fmt.Sprintf("%d-%d/%s", prices[0], prices[1], availability), func(t *testing.T) {
				cfg := &config.Config{Domain: "tunn.to", ProMonthlyUSD: prices[0], ProYearlyUSD: prices[1], BillingEnabled: true, StripeWebhookSecret: "test-secret", StripeCheckoutURLMonthly: "https://buy.stripe.com/month", StripeCheckoutURLYearly: "https://buy.stripe.com/year"}
				// Exercise the same configured transfer cap in the HTML and plain-text tables.
				if prices[0] == 13 {
					cfg.OwnerMonthlyBytes = 123456789
				}
				switch availability {
				case "monthly":
					cfg.StripeCheckoutURLYearly = ""
				case "yearly":
					cfg.StripeCheckoutURLMonthly = ""
				case "disabled":
					cfg.BillingEnabled = false
				case "missing-authority":
					cfg.StripeWebhookSecret = ""
				case "automatic":
					cfg.StripeSecretKey = "sk_test_fixtureautomatic"
					cfg.StripeProPriceIDs = []string{"price_fixtureMonth123", "price_fixtureYear456"}
				case "unsafe":
					cfg.StripeCheckoutURLMonthly = "https://example.com/month"
					cfg.StripeCheckoutURLYearly = "https://example.com/year"
				}
				handler := agentKitHandler(cfg)
				assertAgentKitCheckoutAvailability(t, handler,
					availability == "both" || availability == "monthly" || availability == "automatic",
					availability == "both" || availability == "yearly" || availability == "automatic")
				body, doc := searchPage(t, handler, "/pricing")
				scripts := searchNodes(doc, func(n *html.Node) bool { return n.Data == "script" && searchAttr(n, "type") == "application/ld+json" })
				if len(scripts) != 1 {
					t.Fatalf("JSON-LD script count %d", len(scripts))
				}
				var app struct {
					Context string `json:"@context"`
					Type    string `json:"@type"`
					Offers  []struct {
						Type               string `json:"@type"`
						Name               string
						Price              int
						PriceCurrency      string
						URL                string
						PriceSpecification struct {
							Price                          int
							PriceCurrency, BillingDuration string
						}
					}
				}
				if err := json.Unmarshal([]byte(searchText(scripts[0])), &app); err != nil {
					t.Fatal(err)
				}
				if app.Context != "https://schema.org" || app.Type != "SoftwareApplication" {
					t.Fatalf("unexpected application: %+v", app)
				}
				monthly := regexp.MustCompile(`<div class="price"><b>\$(\d+)</b><span>/ month</span></div>`).FindAllStringSubmatch(body, -1)
				yearly := regexp.MustCompile(`<p class="plan-billing">or \$(\d+) / year</p>`).FindStringSubmatch(body)
				if len(monthly) != 2 || len(yearly) != 2 {
					t.Fatal("missing rendered prices")
				}
				renderedMonthly, _ := strconv.Atoi(monthly[1][1])
				renderedYearly, _ := strconv.Atoi(yearly[1])
				if renderedMonthly != prices[0] || renderedYearly != prices[1] || monthly[0][1] != "0" {
					t.Fatal("configured prices not rendered")
				}
				expected := map[string]int{"Free": 0}
				if availability == "both" || availability == "monthly" || availability == "automatic" {
					expected["Pro monthly"] = renderedMonthly
				}
				if availability == "both" || availability == "yearly" || availability == "automatic" {
					expected["Pro yearly"] = renderedYearly
				}
				if len(app.Offers) != len(expected) {
					t.Fatalf("offers = %+v, want %v", app.Offers, expected)
				}
				for _, offer := range app.Offers {
					price, ok := expected[offer.Name]
					if !ok || offer.Price != price || offer.Type != "Offer" || offer.PriceCurrency != "USD" {
						t.Fatalf("unexpected offer %+v", offer)
					}
					delete(expected, offer.Name)
					if offer.Name != "Free" {
						duration, period := "P1M", "monthly"
						if offer.Name == "Pro yearly" {
							duration, period = "P1Y", "yearly"
						}
						if offer.PriceSpecification.Price != price || offer.PriceSpecification.PriceCurrency != "USD" || offer.PriceSpecification.BillingDuration != duration || offer.URL != "https://tunn.to/upgrade?period="+period {
							t.Fatalf("billing terms %+v", offer)
						}
					}
				}
				// Read limits from the visible comparison table, rather than computing them again.
				sections := searchNodes(doc, func(n *html.Node) bool { return n.Data == "section" && searchAttr(n, "class") == "pricing-comparison" })
				if len(sections) != 1 {
					t.Fatal("missing comparison table")
				}
				rows := searchNodes(sections[0], func(n *html.Node) bool { return n.Data == "tr" })
				var limits [2][]string
				for _, row := range rows[1:] {
					cells := searchNodes(row, func(n *html.Node) bool { return n.Data == "td" })
					if len(cells) != 2 {
						t.Fatal("missing comparison cells")
					}
					for i, cell := range cells {
						value := strings.TrimSpace(searchText(cell))
						if label := strings.Fields(value); len(label) > 0 && (strings.Contains(value, " concurrent tunnels") || strings.Contains(value, " reserved *.tunn.to")) {
							value = label[0]
						}
						limits[i] = append(limits[i], value)
					}
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://tunn.to/llms.txt", nil))
				if w.Code != 200 || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
					t.Fatalf("llms response %d %v", w.Code, w.Header())
				}
				index := w.Body.String()
				for i, plan := range []string{"Free", "Pro"} {
					price := "$0"
					if i == 1 {
						price = fmt.Sprintf("$%d/month or $%d/year", renderedMonthly, renderedYearly)
					}
					want := fmt.Sprintf("| %s | %s | %s | %s | %s | %s |", plan, price, limits[i][0], limits[i][1], limits[i][2], limits[i][3])
					if !strings.Contains(index, want) {
						t.Errorf("llms differs from rendered pricing: missing %q", want)
					}
				}
				for _, want := range []string{"curl -fsSL https://tunn.to/install.sh | sh", "HTTPS access to a local HTTP app or MCP server", "https://tunn.to/docs)", "https://tunn.to/pricing)", "https://tunn.to/client-previews)", "https://tunn.to/mcp-to-claude)", "https://tunn.to/ngrok-alternative)"} {
					if !strings.Contains(index, want) {
						t.Errorf("llms missing %q", want)
					}
				}
			})
		}
	}
}
