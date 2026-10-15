package host

import (
	_ "embed"
	"fmt"
	"io"
	"strings"
)

// baseCSS contains the shared CSS styles for all tunn pages (matches homepage)
//
//go:embed templates/assets/system.css
var baseCSS string

//go:embed templates/assets/header.html
var pageHeader string

const pageFooter = `<footer class="site-footer"><div class="container"><a href="/docs">Docs</a><a href="/pricing">Pricing</a><a href="/status">Status</a><a href="https://gitlab.com/ehrlich-b/tunn">Source</a><span class="spacer"></span><a href="/privacy">Privacy</a><a href="/terms">Terms</a></div></footer>`

// siteHeader returns the shared header with the named section marked current.
func siteHeader(current string) string {
	if current == "" {
		return pageHeader
	}
	return strings.ReplaceAll(pageHeader, `data-nav="`+current+`"`, `data-nav="`+current+`" aria-current="page"`)
}

// withSiteChrome fills the header and footer markers in full-page templates.
func withSiteChrome(page string) string {
	for _, current := range []string{"home", "docs", "pricing", "ngrok", "signin", "status", "none"} {
		page = strings.ReplaceAll(page, "<!--site-header:"+current+"-->", siteHeader(current))
	}
	return strings.ReplaceAll(page, "<!--site-footer-->", pageFooter)
}

// writePageStart writes the HTML head and opening body tags with header
func writePageStart(w io.Writer, title string) {
	writePageStartAt(w, title, "")
}

func writePageStartAt(w io.Writer, title, current string) {
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#FFFFFF"><title>%s</title><style>%s</style></head><body>`, title, baseCSS)
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
