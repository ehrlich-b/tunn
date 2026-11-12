package host

import (
	"encoding/xml"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
	"golang.org/x/net/html"
)

func TestMCPQuestionPages(t *testing.T) {
	cfg := &config.Config{Domain: "tunn.to"}
	p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
	h := p.createHandler()
	request := func(method, origin, path string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, origin+path, nil))
		return w
	}
	pages := []struct{ path, question, description, source string }{
		{"/mcp-connector-url-must-start-with-https", "Why does the Claude connector say “URL must start with https://”?", "A local MCP connector needs a public HTTPS URL. Compare connection routes and publish a local server with tunn.", "https://claude.com/docs/connectors/building/testing"},
		{"/local-mcp-server-claude-mobile", "How can a local MCP server connect to Claude on a phone?", "A local MCP server needs a public HTTPS connector endpoint for claude.ai. Desktop configuration alone does not publish it.", "https://mer.vin/2026/08/local-vs-remote-mcp-how-claude-custom-connectors-work/"},
		{"/claude-connector-bearer-token", "Why can’t a Claude connector send an API key header?", "Fixed connector headers are a limited beta. Most accounts need OAuth with dynamic client registration for a private MCP endpoint.", "https://github.com/vishalsachdev/canvas-mcp/issues/484"},
	}
	clients := []string{
		"Claude web with a personal account and a local document search server 2026-10-29",
		"Claude phone with a personal account and a local project status server 2026-10-29",
		"Claude desktop with an organization account and a local inventory server 2026-10-29",
		"Claude web with an organization account and a local reporting server 2026-10-29",
		"Claude phone with an organization account and a local scheduling server 2026-10-29",
		"Claude desktop with a personal account and a local notes server 2026-10-29",
		"Claude web with a personal account and a local build status server 2026-10-29",
		"Claude phone with a personal account and a local issue search server 2026-10-29",
	}
	var text func(*html.Node) string
	text = func(n *html.Node) string {
		if n.Type == html.TextNode {
			return n.Data
		}
		var s strings.Builder
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			s.WriteString(text(c))
		}
		return s.String()
	}
	parse := func(body string) (map[string]string, map[string]string, []string, []string, string) {
		t.Helper()
		doc, err := html.Parse(strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		meta, links := map[string]string{}, map[string]string{}
		var headings, commands []string
		var visit func(*html.Node)
		visit = func(n *html.Node) {
			if n.Type == html.ElementNode {
				a := map[string]string{}
				for _, attr := range n.Attr {
					a[attr.Key] = attr.Val
				}
				switch n.Data {
				case "meta":
					meta[a["name"]+a["property"]] = a["content"]
				case "link":
					links[a["rel"]] = a["href"]
				case "a":
					links[a["href"]] = text(n)
				case "h1":
					headings = append(headings, text(n))
				case "code":
					if command := text(n); strings.HasPrefix(command, "tunn ") {
						commands = append(commands, command)
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				visit(c)
			}
		}
		visit(doc)
		return meta, links, headings, commands, text(doc)
	}
	for _, state := range []struct {
		name  string
		count int
	}{{"unset", 0}, {"one", 1}, {"limit", 4}, {"long", 8}} {
		t.Run(state.name, func(t *testing.T) {
			t.Setenv("TUNN_MCP_VERIFIED", strings.Join(clients[:state.count], "; "))
			if state.count == 0 {
				if err := os.Unsetenv("TUNN_MCP_VERIFIED"); err != nil {
					t.Fatal(err)
				}
			}
			reference := request("GET", "https://tunn.to", "/mcp-to-claude").Body.String()
			_, _, _, referenceCommands, _ := parse(reference)
			for _, page := range pages {
				t.Run(page.path, func(t *testing.T) {
					w := request("GET", "https://tunn.to", page.path)
					if w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
						t.Fatalf("GET: %d %v", w.Code, w.Header())
					}
					body := w.Body.String()
					meta, links, headings, commands, visibleText := parse(body)
					if links["canonical"] != "https://tunn.to"+page.path || links["stylesheet"] != "/guides.css" {
						t.Errorf("canonical or stylesheet: %v", links)
					}
					for key, want := range map[string]string{"description": page.description, "og:description": page.description, "og:title": page.question, "og:url": "https://tunn.to" + page.path, "og:type": "article", "og:site_name": "tunn"} {
						if meta[key] != want {
							t.Errorf("%s = %q, want %q", key, meta[key], want)
						}
					}
					if len(headings) != 1 || headings[0] != page.question {
						t.Errorf("H1: %v", headings)
					}
					if len(commands) != 2 {
						t.Errorf("expected login and publish commands, got %v", commands)
					}
					for _, command := range commands {
						found := false
						for _, original := range referenceCommands {
							found = found || command == original
						}
						if !found {
							t.Errorf("command absent verbatim from canonical guide: %q", command)
						}
					}
					if word := regexp.MustCompile(`(?i)\b(i|we|our|us)\b`).FindString(visibleText); word != "" {
						t.Errorf("first person word: %q", word)
					}
					for _, want := range []string{"Cloudflare Tunnel", "ngrok", "hosting the server", "Anthropic’s MCP tunnels research preview", "must keep running", "under 25 seconds", "serialized", "TLS ends at the relay", "accessed October 29, 2026", "site-header", "site-footer"} {
						if !strings.Contains(body, want) {
							t.Errorf("missing %q", want)
						}
					}
					for _, link := range []string{"/mcp-to-claude", "/pricing", page.source} {
						if links[link] == "" {
							t.Errorf("missing link %q", link)
						}
					}
					// Compare the complete fact with the canonical guide's rendered fact.
					fact := regexp.MustCompile(`(?s)<p class="note">Experimental:.*?</p>|<div class="note mcp-verification">.*?</div>`).FindString(reference)
					if fact == "" || !strings.Contains(body, fact) {
						t.Error("verification fact differs from canonical renderer")
					}
					if state.count == 0 && (!strings.Contains(body, "Experimental:") || strings.Contains(body, "Verified with:")) || state.count > 0 && (!strings.Contains(body, "Verified with:") || strings.Contains(body, "Experimental:")) {
						t.Error("wrong verification state")
					}
					if state.count == 8 && (!strings.Contains(body, "+4 more") || strings.Contains(body, clients[4])) {
						t.Error("client list overflow is not bounded")
					}
					if dir := os.Getenv("TUNN_QUESTION_PREVIEW_DIR"); dir != "" {
						if err := os.WriteFile(filepath.Join(dir, strings.TrimPrefix(page.path, "/")+"-"+state.name+".html"), []byte(body), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(dir, "guides.css"), []byte(baseCSS+"\n"+guidesCSS), 0600); err != nil {
							t.Fatal(err)
						}
					}
					if head := request("HEAD", "https://tunn.to", page.path); head.Code != 200 || head.Body.Len() != 0 {
						t.Error("invalid HEAD response")
					}
					if post := request("POST", "https://tunn.to", page.path); post.Code != 405 || post.Header().Get("Allow") != "GET, HEAD" {
						t.Error("invalid POST response")
					}
					if offline := request("GET", "https://offline.tunn.to", page.path); offline.Code != 503 || strings.Contains(offline.Body.String(), "<title>") {
						t.Error("guide leaked onto publisher origin")
					}
				})
			}
		})
	}
	w := request("GET", "https://tunn.to", "/sitemap.xml")
	var sitemap struct {
		XMLName xml.Name `xml:"http://www.sitemaps.org/schemas/sitemap/0.9 urlset"`
		URLs    []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &sitemap) != nil {
		t.Fatal("invalid sitemap")
	}
	for _, path := range []string{pages[0].path, pages[1].path, pages[2].path, "/pricing", "/docs", "/about"} {
		found := false
		for _, u := range sitemap.URLs {
			found = found || u.Loc == "https://tunn.to"+path
		}
		if !found {
			t.Errorf("sitemap missing %s", path)
		}
	}
}
