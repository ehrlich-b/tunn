package host

import (
	_ "embed"
	"fmt"
	"io"
)

// baseCSS contains the shared CSS styles for all tunn pages (matches homepage)
//
//go:embed templates/assets/system.css
var baseCSS string

//go:embed templates/assets/header.html
var pageHeader string

// writePageStart writes the HTML head and opening body tags with header
func writePageStart(w io.Writer, title string) {
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><link rel="preload" href="/assets/space-grotesk-latin-600-normal.woff2" as="font" type="font/woff2" crossorigin><link rel="stylesheet" href="/assets/system.css"><script src="/assets/theme.js"></script><script defer src="/assets/ui.js"></script></head><body>`, title)
	_, _ = fmt.Fprint(w, pageHeader, `<main id="main" class="page-container">`)
}

// writePageEnd writes the closing body and html tags
func writePageEnd(w io.Writer) {
	_, _ = fmt.Fprint(w, `</main>
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
