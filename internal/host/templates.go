package host

import (
	_ "embed"
	"fmt"
	"html"
	"html/template"
	"io"
	"strings"

	"github.com/ehrlich-b/tunn/internal/config"
)

// baseCSS contains the shared CSS styles for all tunn pages (matches homepage)
//
//go:embed templates/assets/system.css
var baseCSS string

//go:embed templates/assets/header.html
var pageHeader string

const pageFooter = `<footer class="site-footer"><div class="container"><a href="/about">About &amp; support</a><a href="/docs">Docs</a><a href="/pricing">Pricing</a><a href="/status">Status</a><a href="https://gitlab.com/ehrlich-b/tunn">Source</a><span class="spacer"></span><a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/report">Report a bug</a><a href="mailto:support@tunn.to">Support</a></div></footer>`

// siteHeader returns the shared header with the named section marked current.
func siteHeader(current string) string {
	if current == "" {
		return pageHeader
	}
	return strings.ReplaceAll(pageHeader, `data-nav="`+current+`"`, `data-nav="`+current+`" aria-current="page"`)
}

// withSiteChrome fills the header and footer markers in full-page templates.
func withSiteChrome(page string) string {
	page = withMCPVerification(page)
	for _, current := range []string{"home", "docs", "pricing", "ngrok", "signin", "status", "none"} {
		page = strings.ReplaceAll(page, "<!--site-header:"+current+"-->", siteHeader(current))
	}
	return withPageHead(strings.ReplaceAll(page, "<!--site-footer-->", pageFooter))
}

// withMCPVerification fills only the MCP guide's fact fragment. Both static guide
// routes already use this template layer, so their handlers need no special case.
func withMCPVerification(page string) string {
	before, rest, found := strings.Cut(page, "<!--mcp-verification-->")
	if !found {
		return page
	}
	fragment, after, found := strings.Cut(rest, "<!--/mcp-verification-->")
	if !found {
		return page
	}
	var data struct {
		Clients []string
		More    int
	}
	value := strings.TrimSpace(config.MCPVerifiedFromEnv())
	if value != "" {
		for _, client := range strings.Split(value, ";") {
			if client = strings.TrimSpace(client); client != "" {
				data.Clients = append(data.Clients, client)
			}
		}
		if len(data.Clients) == 0 {
			data.Clients = []string{value}
		}
		const visibleClients = 4
		if len(data.Clients) > visibleClients {
			data.More = len(data.Clients) - visibleClients
			data.Clients = data.Clients[:visibleClients]
		}
	}
	var note strings.Builder
	tmpl := template.Must(template.New("mcp-verification").Parse(fragment))
	if err := tmpl.Execute(&note, data); err != nil {
		// The fragment and data shape are bundled together; failures are programming errors.
		panic(err)
	}
	return before + note.String() + after
}

// iconHead is shared by every server-rendered document.
const iconHead = `<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">
<link rel="icon" type="image/svg+xml" href="/assets/favicon.svg" sizes="any">
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" sizes="180x180">
<link rel="manifest" href="/assets/site.webmanifest">`

// platformIconHead keeps platform assets reachable on publisher and customer hosts.
func platformIconHead(authority string) string {
	if authority == "" {
		return iconHead
	}
	return strings.ReplaceAll(iconHead, `href="/`, `href="https://`+html.EscapeString(authority)+`/`)
}

func withPageHead(page string) string {
	return strings.Replace(page, "</head>", iconHead+"</head>", 1)
}

// writePageStart writes the HTML head and opening body tags with header
func writePageStart(w io.Writer, title string) {
	writePageStartAt(w, title, "")
}

func writePageStartAt(w io.Writer, title, current string) {
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#FFFFFF"><title>%s</title><style>%s</style>%s</head><body>`, title, baseCSS, iconHead)
	_, _ = fmt.Fprint(w, siteHeader(current), `<main id="main" class="page-container">`)
}

// writePageEnd writes the closing body and html tags
func writePageEnd(w io.Writer) {
	_, _ = fmt.Fprint(w, `</main>`, pageFooter, `<script defer src="/assets/ui.js"></script>
</body>
</html>`)
}

// writeSuccessPage writes a complete success page
func writeSuccessPage(w io.Writer, title, message string) {
	writePageStart(w, "tunn - "+title)
	_, _ = fmt.Fprintf(w, `<div class="message success">%s</div>
<h1 class="page-title">%s</h1>
<p class="page-subtitle">%s</p>
`, message, title, message)
	_, _ = fmt.Fprint(w, `<a href="/" class="btn btn-primary">Back to Home</a>`)
	writePageEnd(w)
}
