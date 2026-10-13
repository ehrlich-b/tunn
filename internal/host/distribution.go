package host

import (
	_ "embed"
	"fmt"
	"net/http"
)

//go:embed templates/ngrok-alternative.html
var ngrokAlternativeHTML string

//go:embed templates/mcp-to-claude.html
var mcpToClaudeHTML string

//go:embed templates/share-dev-server-oauth.html
var shareDevServerOAuthHTML string

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
	case "/ngrok-alternative":
		body = ngrokAlternativeHTML
	case "/mcp-to-claude":
		body = mcpToClaudeHTML
	case "/share-dev-server-oauth":
		body = shareDevServerOAuthHTML
	case "/guides.css":
		contentType, body = "text/css; charset=utf-8", baseCSS+"\n"+guidesCSS
	case "/robots.txt":
		contentType, body = "text/plain; charset=utf-8", "User-agent: *\nAllow: /\nSitemap: https://tunn.to/sitemap.xml\n"
	case "/sitemap.xml":
		contentType, body = "application/xml; charset=utf-8", distributionSitemap
	default:
		return false
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
	if r.URL.Path == "/ngrok-alternative" {
		p.renderRevenuePage(w, body)
	} else {
		_, _ = fmt.Fprint(w, body)
	}
	return true
}

const distributionSitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://tunn.to/</loc></url>
  <url><loc>https://tunn.to/ngrok-alternative</loc></url>
  <url><loc>https://tunn.to/mcp-to-claude</loc></url>
  <url><loc>https://tunn.to/share-dev-server-oauth</loc></url>
  <url><loc>https://tunn.to/privacy</loc></url>
  <url><loc>https://tunn.to/terms</loc></url>
</urlset>
`
