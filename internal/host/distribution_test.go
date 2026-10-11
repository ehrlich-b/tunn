package host

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
	"golang.org/x/net/html"
)

func TestDistributionPages(t *testing.T) {
	cfg := &config.Config{Domain: "tunn.to"}
	proxy := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
	handler := proxy.createHandler()
	paths := []string{"/ngrok-alternative", "/mcp-to-claude", "/share-dev-server-oauth"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to"+path, nil))
			if w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
				t.Fatalf("page response: %d %v", w.Code, w.Header())
			}
			doc, err := html.Parse(strings.NewReader(w.Body.String()))
			if err != nil {
				t.Fatal(err)
			}
			meta, links := map[string]string{}, map[string]bool{}
			var title, headings int
			var visit func(*html.Node)
			visit = func(n *html.Node) {
				if n.Type == html.ElementNode {
					attrs := map[string]string{}
					for _, a := range n.Attr {
						attrs[a.Key] = a.Val
					}
					switch n.Data {
					case "title":
						if n.FirstChild != nil && strings.TrimSpace(n.FirstChild.Data) != "" {
							title++
						}
					case "h1":
						headings++
					case "meta":
						meta[attrs["name"]+attrs["property"]] = attrs["content"]
					case "link":
						meta[attrs["rel"]] = attrs["href"]
					case "a":
						links[attrs["href"]] = true
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					visit(c)
				}
			}
			visit(doc)
			if title != 1 || headings != 1 {
				t.Fatalf("title count=%d, h1 count=%d", title, headings)
			}
			for _, key := range []string{"description", "og:title", "og:description", "og:type", "og:site_name"} {
				if meta[key] == "" {
					t.Errorf("missing %s", key)
				}
			}
			for _, key := range []string{"canonical", "og:url"} {
				if meta[key] != "https://tunn.to"+path {
					t.Errorf("%s=%q", key, meta[key])
				}
			}
			if meta["stylesheet"] != "/guides.css" {
				t.Fatal("missing guide stylesheet")
			}
			for _, link := range paths {
				if !links[link] || !strings.Contains(homepageHTML, `href="`+link+`"`) {
					t.Errorf("guide navigation missing %s", link)
				}
			}
			// The platform must never claim a publisher's path, even a guide path.
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "https://offline.tunn.to"+path, nil))
			if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "<title>") {
				t.Fatalf("guide leaked onto tunnel origin: %d", w.Code)
			}
		})
	}
	for _, path := range append(paths, "/guides.css", "/sitemap.xml", "/robots.txt") {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("HEAD", "https://tunn.to"+path, nil))
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Errorf("HEAD %s: %d, body=%q", path, w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", "https://tunn.to"+path, nil))
		if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("POST %s: %d %v", path, w.Code, w.Header())
		}
	}
	for path, contentType := range map[string]string{"/guides.css": "text/css; charset=utf-8", "/robots.txt": "text/plain; charset=utf-8", "/sitemap.xml": "application/xml; charset=utf-8"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to"+path, nil))
		if w.Code != 200 || w.Header().Get("Content-Type") != contentType || w.Body.Len() == 0 {
			t.Errorf("asset %s: %d %v", path, w.Code, w.Header())
		}
		if path == "/robots.txt" && !strings.Contains(w.Body.String(), "Sitemap: https://tunn.to/sitemap.xml") {
			t.Error("robots does not advertise sitemap")
		}
		if path == "/sitemap.xml" {
			var sitemap struct {
				XMLName xml.Name `xml:"http://www.sitemaps.org/schemas/sitemap/0.9 urlset"`
				URLs    []struct {
					Loc string `xml:"loc"`
				} `xml:"url"`
			}
			if err := xml.Unmarshal(w.Body.Bytes(), &sitemap); err != nil {
				t.Fatal(err)
			}
			for _, guide := range paths {
				found := false
				for _, url := range sitemap.URLs {
					found = found || url.Loc == "https://tunn.to"+guide
				}
				if !found {
					t.Errorf("sitemap missing %s", guide)
				}
			}
		}
	}
}
