package host

import (
	"encoding/xml"
	"fmt"
	"html"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
	xhtml "golang.org/x/net/html"
)

func clientPreviewProxy(cfg *config.Config) *ProxyServer {
	return &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
}

func TestClientPreviewPage(t *testing.T) {
	cfg := &config.Config{Domain: "tunn.to", ProMonthlyUSD: 5, ProYearlyUSD: 48}
	p := clientPreviewProxy(cfg)
	h := p.createHandler()
	get := func(method, path string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, "https://tunn.to"+path, nil))
		return w
	}
	w := get("GET", "/client-previews")
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("route: %d %v", w.Code, w.Header())
	}
	body := w.Body.String()
	d := p.revenueData()
	for _, want := range []string{
		`rel="canonical" href="https://tunn.to/client-previews"`,
		`tunn 3000 --name north-preview <span style="white-space:nowrap">--allow=` + html.EscapeString("client@example.com") + `</span>`,
		"tunn login", "curl -fsSL https://tunn.to/install.sh | sh",
		"Keep both your local app and tunn running", "signs in with the allowed email",
		"Replace", "with an available name", "with your client's email",
		fmt.Sprintf("Free keeps %d name; Pro keeps %d names", d.FreeReservations, d.Reservations),
		fmt.Sprintf("$%d/month or $%d/year", d.MonthlyUSD, d.YearlyUSD),
		fmt.Sprintf("%d concurrent tunnels", d.FreeTunnels), fmt.Sprintf("Pro includes %d and %s", d.ProTunnels, d.ProBytesShort),
		d.FreeBytesShort, d.FreeRequestsShort, "reserves ownership while", "does not host your app", "Random names count", "email support",
		"shortening", "does not remove earlier grants", "relay terminates TLS",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	doc, err := xhtml.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	links := map[string]bool{}
	var visit func(*xhtml.Node)
	visit = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" {
					u, err := url.Parse(a.Val)
					if err != nil || u == nil || u.Host != "" && u.Scheme != "https" || u.Scheme != "" && u.Scheme != "https" && u.Scheme != "mailto" || strings.HasPrefix(a.Val, "//") {
						t.Errorf("unsafe link %q", a.Val)
					}
					links[a.Val] = true
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(doc)
	for _, link := range []string{"#first-preview", "/pricing", "/account/sharing", "mailto:support@tunn.to"} {
		if !links[link] {
			t.Errorf("missing link %s", link)
		}
	}
	for _, path := range []string{"/docs", "/pricing"} {
		if !strings.Contains(get("GET", path).Body.String(), `href="/client-previews"`) {
			t.Errorf("missing discovery on %s", path)
		}
	}
	if w := get("HEAD", "/client-previews"); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("HEAD", w.Code, w.Body.String())
	}
	if w := get("POST", "/client-previews"); w.Code != 405 {
		t.Fatal("POST", w.Code)
	}
	offline := httptest.NewRecorder()
	h.ServeHTTP(offline, httptest.NewRequest("GET", "https://offline.tunn.to/client-previews", nil))
	if offline.Code != 503 || strings.Contains(offline.Body.String(), "<title>") {
		t.Fatal("page leaked to publisher", offline.Code)
	}
	if dir := os.Getenv("TUNN_CLIENT_PREVIEW_EVIDENCE"); dir != "" {
		for name, data := range map[string]string{"client-previews.html": body, "guides.css": baseCSS + "\n" + guidesCSS} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	cfg.ProMonthlyUSD = 7
	cfg.ProYearlyUSD = 71
	cfg.OwnerMonthlyBytes = 500000000
	changed := get("GET", "/client-previews").Body.String()
	for _, want := range []string{"$7/month or $71/year", p.revenueData().FreeBytesShort, p.revenueData().ProBytesShort} {
		if !strings.Contains(changed, want) {
			t.Errorf("config not reflected: %s", want)
		}
	}
	// Preserve the existing account-bound upgrade destination after sign-in.
	redirect := get("GET", "/upgrade?period=yearly")
	if redirect.Code != 302 || !strings.Contains(redirect.Header().Get("Location"), "return_to=%2Fupgrade%3Fperiod%3Dyearly") {
		t.Fatal("upgrade return lost", redirect.Code, redirect.Header())
	}
}

func TestClientPreviewSitemap(t *testing.T) {
	p := clientPreviewProxy(&config.Config{Domain: "tunn.to"})
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to/sitemap.xml", nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/xml; charset=utf-8" {
		t.Fatal(w.Code, w.Header())
	}
	var sitemap struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal(w.Body.Bytes(), &sitemap); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, u := range sitemap.URLs {
		if u.Loc == "https://tunn.to/client-previews" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("client preview sitemap entries: %d", count)
	}
}
