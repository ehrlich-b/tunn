package host

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

//go:embed templates/ngrok-alternative.html
var ngrokAlternativeHTML string

//go:embed templates/client-previews.html
var clientPreviewsHTML string

//go:embed templates/mcp-to-claude.html
var mcpToClaudeHTML string

var mcpToClaudeTemplate = template.Must(template.New("mcp-to-claude").Parse(withSiteChrome(mcpToClaudeHTML)))

func (p *ProxyServer) renderMCPToClaude(w http.ResponseWriter) {
	var verified string
	if p.config != nil {
		verified = strings.TrimSpace(p.config.MCPVerified)
	}
	if err := mcpToClaudeTemplate.Execute(w, struct{ MCPVerified string }{verified}); err != nil {
		http.Error(w, "Page unavailable", http.StatusInternalServerError)
	}
}

//go:embed templates/share-dev-server-oauth.html
var shareDevServerOAuthHTML string

//go:embed templates/assets/echo.py
var mcpEchoPython []byte

// handleMCPEchoExample serves the bundled example without release-feed lookup.
func handleMCPEchoExample(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="echo.py"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(mcpEchoPython)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(mcpEchoPython)
	}
}

//go:embed templates/agents/AGENTS.md
var agentsMarkdown string

//go:embed templates/agents/SKILLS.md
var agentsSkillsMarkdown string

//go:embed templates/guides.css
var guidesCSS string

// Only the apex router calls this handler; publishers keep all their own paths.
func (p *ProxyServer) serveDistributionPage(w http.ResponseWriter, r *http.Request) bool {
	if serveWebAsset(w, r) {
		return true
	}
	contentType := "text/html; charset=utf-8"
	var body string
	switch r.URL.Path {
	case "/llms.txt":
		contentType, body = "text/plain; charset=utf-8", p.agentKitIndex()
	case "/client-previews":
		body = clientPreviewsHTML
	case "/ngrok-alternative":
		body = ngrokAlternativeHTML
	case "/mcp-to-claude":
		body = withSiteChrome(mcpToClaudeHTML)
	case "/share-dev-server-oauth":
		body = withSiteChrome(shareDevServerOAuthHTML)
	case "/guides.css":
		contentType, body = "text/css; charset=utf-8", baseCSS+"\n"+guidesCSS
	case "/robots.txt":
		contentType, body = "text/plain; charset=utf-8", "User-agent: *\nAllow: /\nSitemap: https://tunn.to/sitemap.xml\n"
	case "/sitemap.xml":
		contentType, body = "application/xml; charset=utf-8", distributionSitemap
	default:
		found := false
		for _, page := range agentKitPages {
			if r.URL.Path == page.path {
				contentType, body = "text/markdown; charset=utf-8", page.body
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	w.Header().Set("Content-Type", contentType)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return true
	}
	if r.URL.Path == "/ngrok-alternative" || r.URL.Path == "/client-previews" {
		p.renderRevenuePage(w, body)
	} else if r.URL.Path == "/mcp-to-claude" {
		p.renderMCPToClaude(w)
	} else {
		_, _ = fmt.Fprint(w, body)
	}
	return true
}

const distributionSitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://tunn.to/</loc></url>
  <url><loc>https://tunn.to/client-previews</loc></url>
  <url><loc>https://tunn.to/ngrok-alternative</loc></url>
  <url><loc>https://tunn.to/mcp-to-claude</loc></url>
  <url><loc>https://tunn.to/share-dev-server-oauth</loc></url>
  <url><loc>https://tunn.to/privacy</loc></url>
  <url><loc>https://tunn.to/terms</loc></url>
</urlset>
`
