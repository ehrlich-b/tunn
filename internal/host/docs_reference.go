package host

import (
	_ "embed"
	"fmt"
	"html"
	"io"
	"strings"
)

//go:embed templates/docs.css
var docsCSS string

//go:embed templates/docs-sharing.html
var docsSharingHTML string

//go:embed templates/docs-ssh.html
var docsSSHHTML string

//go:embed templates/docs-limits.html
var docsLimitsHTML string

//go:embed templates/docs-troubleshooting.html
var docsTroubleshootingHTML string

//go:embed templates/docs-cli.html
var docsCLIHTML string

type referencePage struct {
	title, body string
	revenue     bool
}

// The standalone journey remains the one authored source for both entry points.
func mcpGuideBody() string {
	_, body, ok := strings.Cut(mcpToClaudeHTML, "<main>")
	if !ok {
		panic("MCP guide is missing main")
	}
	body, _, ok = strings.Cut(body, "</main>")
	if !ok {
		panic("MCP guide is missing closing main")
	}
	return body
}

var referencePages = map[string]referencePage{
	"/docs":                      {"Quickstart", docsHTML, false},
	"/docs/":                     {"Quickstart", docsHTML, false},
	"/docs/mcp-to-claude":        {"MCP to Claude.ai and ChatGPT", mcpGuideBody(), false},
	"/docs/sharing":              {"Share with a person", docsSharingHTML, false},
	"/docs/ssh":                  {"SSH without tunn", docsSSHHTML, false},
	"/docs/limits":               {"Pricing and limits", docsLimitsHTML, true},
	"/docs/cli":                  {"CLI reference", docsCLIHTML, false},
	"/docs/troubleshooting":      {"Troubleshooting", docsTroubleshootingHTML, false},
	"/docs/webhook-verification": {"Verify webhooks", webhookDocsHTML, false},
	"/docs/ip-restrictions":      {"IP restrictions", ipRestrictionsHTML, false},
	"/docs/status":               {"Status measurements", statusDocsHTML, false},
	"/docs/docker":               {"Docker client", dockerDocsHTML, false},
}

var docsLinks = []struct{ path, title string }{
	{"/docs", "Quickstart"},
	{"/docs/sharing", "Share with a person"},
	{"/docs/mcp-to-claude", "MCP connectors"},
	{"/docs/webhook-verification", "Verified webhooks"},
	{"/docs/ssh", "SSH without tunn"},
	{"/docs/limits", "Pricing & limits"},
	{"/docs/cli", "CLI reference"},
	{"/docs/troubleshooting", "Troubleshooting"},
}

func writeDocsNav(w io.Writer, path, class string) {
	_, _ = fmt.Fprintf(w, `<nav class="%s" aria-label="Documentation">`, class)
	for _, link := range docsLinks {
		current := ""
		if path == link.path || path == "/docs/" && link.path == "/docs" {
			current = ` aria-current="page"`
		}
		_, _ = fmt.Fprintf(w, `<a href="%s"%s>%s</a>`, link.path, current, html.EscapeString(link.title))
	}
	_, _ = fmt.Fprint(w, `</nav>`)
}

func writeDocsStart(w io.Writer, path string) {
	_, _ = fmt.Fprintf(w, `<style>%s</style><a class="docs-skip" href="#docs-content">Skip to content</a><div class="docs-layout"><aside class="docs-sidebar"><p class="docs-label">Documentation</p>`, docsCSS)
	writeDocsNav(w, path, "docs-desktop-nav")
	_, _ = fmt.Fprint(w, `<details class="docs-mobile-nav"><summary>Browse docs</summary>`)
	writeDocsNav(w, path, "")
	_, _ = fmt.Fprint(w, `</details></aside><main class="docs-content" id="docs-content">`)
}
