package host

import (
	_ "embed"
)

//go:embed templates/homepage.html
var homepageHTML string

//go:embed templates/privacy.html
var privacyHTML string

//go:embed templates/terms.html
var termsHTML string

//go:embed templates/account.html
var accountHTML string

//go:embed templates/pricing.html
var pricingHTML string

//go:embed templates/docs.html
var docsHTML string

//go:embed templates/revenue-mcp-to-claude.html
var mcpTutorialHTML string

//go:embed templates/webhook-verification.html
var webhookDocsHTML string
