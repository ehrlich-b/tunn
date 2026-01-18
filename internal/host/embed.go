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
