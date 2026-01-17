package host

import (
	"fmt"
	"io"
)

// baseCSS contains the shared CSS styles for all tunn pages
const baseCSS = `
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
  background: #0d1117;
  color: #c9d1d9;
  line-height: 1.6;
  margin: 0;
  padding: 40px;
}
.container { max-width: 500px; margin: 80px auto; }
.logo { font-size: 24px; font-weight: bold; color: #58a6ff; margin-bottom: 32px; }
h1 { font-size: 20px; font-weight: normal; margin: 0 0 24px 0; }
p { color: #8b949e; margin: 0 0 12px 0; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
code { background: #161b22; padding: 2px 6px; border-radius: 4px; color: #c9d1d9; }

/* Buttons */
.btn {
  display: block;
  width: 100%;
  padding: 12px 16px;
  border-radius: 6px;
  text-decoration: none;
  text-align: center;
  font-size: 14px;
  font-family: inherit;
  cursor: pointer;
  box-sizing: border-box;
  margin-bottom: 12px;
}
.btn-github { background: #238636; color: white; border: none; }
.btn-github:hover { background: #2ea043; }
.btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
.btn-secondary:hover { background: #30363d; }

/* Forms */
input[type="email"], input[type="text"] {
  width: 100%;
  padding: 12px 16px;
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 6px;
  color: #c9d1d9;
  font-size: 14px;
  font-family: inherit;
  box-sizing: border-box;
  margin-bottom: 12px;
}
input:focus { outline: none; border-color: #58a6ff; }

/* Divider */
.divider { display: flex; align-items: center; margin: 20px 0; color: #8b949e; }
.divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid #30363d; }
.divider span { padding: 0 16px; font-size: 12px; }

/* Messages */
.message { padding: 12px; border-radius: 6px; margin-bottom: 16px; font-size: 14px; }
.message.success { background: #238636; color: white; }
.message.error { background: #da3633; color: white; }

/* Error state */
.error-title { color: #f85149; }
`

// writePageStart writes the HTML head and opening body tags
func writePageStart(w io.Writer, title string) {
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>%s</style>
</head>
<body>
<div class="container">
<div class="logo">tunn</div>
`, title, baseCSS)
}

// writePageEnd writes the closing body and html tags
func writePageEnd(w io.Writer) {
	fmt.Fprint(w, `</div>
</body>
</html>`)
}

// writeErrorPage writes a complete error page
func writeErrorPage(w io.Writer, title, message, detail string) {
	writePageStart(w, "tunn - "+title)
	fmt.Fprintf(w, `<h1 class="error-title">%s</h1>
<p>%s</p>
`, title, message)
	if detail != "" {
		fmt.Fprintf(w, `<p><code>%s</code></p>
`, detail)
	}
	writePageEnd(w)
}

// writeSuccessPage writes a complete success page
func writeSuccessPage(w io.Writer, title, message string) {
	writePageStart(w, "tunn - "+title)
	fmt.Fprintf(w, `<h1>%s</h1>
<p>%s</p>
`, title, message)
	writePageEnd(w)
}
