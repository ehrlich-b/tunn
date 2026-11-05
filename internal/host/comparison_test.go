package host

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"golang.org/x/net/html"
)

var comparisonPaths = []string{"/cloudflare-quick-tunnel-alternative", "/tailscale-funnel-alternative"}

func comparisonProxy(cfg *config.Config) *ProxyServer {
	return &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
}

func comparisonDocument(t *testing.T, body string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func comparisonWalk(n *html.Node, visit func(*html.Node)) {
	visit(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		comparisonWalk(c, visit)
	}
}

func comparisonAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func comparisonText(n *html.Node) string {
	var b strings.Builder
	comparisonWalk(n, func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
	})
	return b.String()
}

func TestComparisonPages(t *testing.T) {
	cfg := &config.Config{Domain: "tunn.to", OwnerMonthlyBytes: 3_000_000_000}
	handler := comparisonProxy(cfg).createHandler()
	for _, path := range comparisonPaths {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to"+path, nil))
			body := w.Body.String()
			if w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
				t.Fatalf("GET: %d %v", w.Code, w.Header())
			}
			for _, want := range []string{"Hosted clients are not yet verified", "Free: 5 concurrent tunnels, 3 GB transfer", "2026-11-05"} {
				if !strings.Contains(body, want) {
					t.Errorf("missing rendered fact %q", want)
				}
			}
			if !strings.Contains(body, `<header class="site-header">`) || strings.Contains(body, "<!--site-header:") {
				t.Error("missing shared header")
			}
			if strings.Contains(body, "{{") {
				t.Fatal("unrendered config")
			}
			doc := comparisonDocument(t, body)
			headings, titles, rows := 0, 0, 0
			meta := map[string]string{}
			comparisonWalk(doc, func(n *html.Node) {
				if n.Type != html.ElementNode {
					return
				}
				switch n.Data {
				case "h1":
					headings++
				case "title":
					titles++
				case "meta":
					meta[comparisonAttr(n, "name")+comparisonAttr(n, "property")] = comparisonAttr(n, "content")
				case "link":
					meta[comparisonAttr(n, "rel")] = comparisonAttr(n, "href")
				case "td":
					rows++
					sources := 0
					comparisonWalk(n, func(c *html.Node) {
						if c.Type == html.ElementNode && c.Data == "a" && comparisonAttr(c, "class") == "fact-source" {
							url := comparisonAttr(c, "href")
							allowed := strings.HasPrefix(url, "https://tunn.to/")
							if path == comparisonPaths[0] {
								allowed = allowed || url == "https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/"
							} else {
								allowed = allowed || url == "https://tailscale.com/docs/features/tailscale-funnel" || url == "https://tailscale.com/docs/features/tailscale-serve"
							}
							if !allowed || !strings.Contains(comparisonText(c), "accessed 2026-11-05") {
								t.Errorf("undated/non-primary source %s", url)
							}
							sources++
						}
					})
					if sources == 0 {
						t.Errorf("unsourced comparison cell: %s", comparisonText(n))
					}
				}
			})
			if headings != 1 || titles != 1 || rows != 16 {
				t.Errorf("h1=%d title=%d cells=%d", headings, titles, rows)
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
				t.Error("missing stylesheet")
			}
			if !strings.Contains(ngrokAlternativeHTML, `href="`+path+`"`) {
				t.Error("ngrok comparison missing link")
			}
			for _, method := range []string{"HEAD", "POST"} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(method, "https://tunn.to"+path, nil))
				if method == "HEAD" && (w.Code != 200 || w.Body.Len() != 0) {
					t.Errorf("HEAD: %d %q", w.Code, w.Body.String())
				}
				if method == "POST" && (w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD") {
					t.Errorf("POST: %d %v", w.Code, w.Header())
				}
			}
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "https://offline.tunn.to"+path, nil))
			if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "<title>") {
				t.Fatalf("page leaked to publisher: %d", w.Code)
			}
		})
	}
	// Optional browser artifacts use the actual router and default configuration.
	if dir := os.Getenv("TUNN_COMPARISON_FIXTURE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		handler := comparisonProxy(&config.Config{Domain: "tunn.to"}).createHandler()
		for _, path := range append(append([]string{}, comparisonPaths...), "/guides.css", "/assets/ui.js", "/ngrok-alternative") {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to"+path, nil))
			if w.Code != 200 {
				t.Fatalf("fixture %s: %d", path, w.Code)
			}
			name := strings.TrimPrefix(path, "/")
			if !strings.Contains(name, ".") {
				name += ".html"
			}
			dest := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dest, w.Body.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestComparisonSitemap(t *testing.T) {
	handler := comparisonProxy(&config.Config{Domain: "tunn.to"}).createHandler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to/sitemap.xml", nil))
	var sitemap struct {
		XMLName xml.Name `xml:"http://www.sitemaps.org/schemas/sitemap/0.9 urlset"`
		URLs    []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &sitemap) != nil {
		t.Fatal("invalid sitemap")
	}
	for _, path := range comparisonPaths {
		n := 0
		for _, url := range sitemap.URLs {
			if url.Loc == "https://tunn.to"+path {
				n++
			}
		}
		if n != 1 {
			t.Errorf("sitemap %s count=%d", path, n)
		}
	}
}

// Execute every displayed command with a newly built binary and no credentials.
// Exit 78 proves parsing reached the login boundary without publishing or a dialog.
func TestComparisonCommandsBuiltBinary(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "tunn")
	build := exec.Command("go", "build", "-p", "2", "-o", binary, ".")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	checked := 0
	for _, page := range []string{cloudflareQuickTunnelAlternativeHTML, tailscaleFunnelAlternativeHTML} {
		comparisonWalk(comparisonDocument(t, page), func(n *html.Node) {
			if n.Type != html.ElementNode || n.Data != "code" || comparisonAttr(n, "data-comparison-command") == "" {
				return
			}
			command := comparisonText(n)
			args := strings.Fields(command)
			if len(args) < 2 || args[0] != "tunn" {
				t.Fatalf("unexpected command %q", command)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, args[1:]...)
			cmd.Dir = dir
			cmd.Env = []string{"HOME=" + dir, "TUNN_CONFIG_DIR=" + filepath.Join(dir, "credentials"), "TUNN_SERVER_ADDR=127.0.0.1:1", "PATH=" + os.Getenv("PATH")}
			out, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 78 || !strings.Contains(string(out), "tunn login") {
				t.Errorf("%q did not reach login boundary: %v\n%s", command, err, out)
			}
			t.Logf("parsed with built binary: %s", command)
			checked++
		})
	}
	if checked != 6 {
		t.Fatalf("checked %d commands", checked)
	}
}
