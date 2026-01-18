package host

import (
	_ "embed"
)

//go:embed templates/homepage.html
var homepageHTML string
