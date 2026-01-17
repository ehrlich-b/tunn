package host

import (
	"fmt"
	"io"
)

// baseCSS contains the shared CSS styles for all tunn pages (matches homepage)
const baseCSS = `
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  background: #ffffff;
  color: #1f2328;
  line-height: 1.6;
  margin: 0;
}
code, pre {
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
}
a { color: #0969da; text-decoration: none; }
a:hover { text-decoration: underline; }

/* Header */
.header {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  background: rgba(255,255,255,0.95);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid #d1d9e0;
  z-index: 100;
  padding: 16px 24px;
}
.header-inner {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.header-logo {
  font-size: 20px;
  font-weight: 700;
  color: #1f2328;
  text-decoration: none;
}
.header-nav { display: flex; gap: 24px; align-items: center; }
.header-nav a { color: #57606a; font-size: 14px; font-weight: 500; }
.header-nav a:hover { color: #1f2328; text-decoration: none; }

/* Main content */
.page-container {
  max-width: 440px;
  margin: 0 auto;
  padding: 120px 24px 60px;
}
.page-title {
  font-size: 24px;
  font-weight: 600;
  margin-bottom: 8px;
  color: #1f2328;
}
.page-subtitle {
  color: #57606a;
  margin-bottom: 32px;
  font-size: 15px;
}

/* Buttons */
.btn {
  display: block;
  width: 100%;
  padding: 12px 16px;
  border-radius: 6px;
  text-decoration: none;
  text-align: center;
  font-size: 14px;
  font-weight: 500;
  font-family: inherit;
  cursor: pointer;
  box-sizing: border-box;
  margin-bottom: 12px;
  border: none;
}
.btn:hover { text-decoration: none; }
.btn-primary { background: #0969da; color: white; }
.btn-primary:hover { background: #0860ca; }
.btn-github { background: #24292f; color: white; }
.btn-github:hover { background: #32383f; }
.btn-secondary { background: #f6f8fa; color: #24292f; border: 1px solid #d1d9e0; }
.btn-secondary:hover { background: #eaeef2; }

/* Forms */
input[type="email"], input[type="text"] {
  width: 100%;
  padding: 12px 16px;
  background: #ffffff;
  border: 1px solid #d1d9e0;
  border-radius: 6px;
  color: #1f2328;
  font-size: 14px;
  font-family: inherit;
  box-sizing: border-box;
  margin-bottom: 12px;
}
input:focus { outline: none; border-color: #0969da; box-shadow: 0 0 0 3px rgba(9,105,218,0.15); }
input::placeholder { color: #8c959f; }

/* Divider */
.divider { display: flex; align-items: center; margin: 24px 0; color: #8c959f; }
.divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid #d1d9e0; }
.divider span { padding: 0 16px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }

/* Messages */
.message { padding: 12px 16px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }
.message.success { background: #dafbe1; color: #1a7f37; border: 1px solid #aceebb; }
.message.error { background: #ffebe9; color: #cf222e; border: 1px solid #ffcecb; }
.message.info { background: #ddf4ff; color: #0969da; border: 1px solid #80ccff; }

/* Code */
code { background: #f6f8fa; padding: 2px 6px; border-radius: 4px; color: #1f2328; font-size: 13px; }

/* Card */
.card {
  background: #ffffff;
  border: 1px solid #d1d9e0;
  border-radius: 12px;
  padding: 32px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
`

// writePageStart writes the HTML head and opening body tags with header
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
<header class="header">
  <div class="header-inner">
    <a href="/" class="header-logo">tunn</a>
    <nav class="header-nav">
      <a href="https://github.com/ehrlich-b/tunn">Code</a>
    </nav>
  </div>
</header>
<div class="page-container">
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
	fmt.Fprintf(w, `<div class="message error">%s</div>
<h1 class="page-title">%s</h1>
<p class="page-subtitle">%s</p>
`, message, title, message)
	if detail != "" {
		fmt.Fprintf(w, `<p><code>%s</code></p>
`, detail)
	}
	fmt.Fprint(w, `<a href="/" class="btn btn-secondary">Back to Home</a>`)
	writePageEnd(w)
}

// writeSuccessPage writes a complete success page
func writeSuccessPage(w io.Writer, title, message string) {
	writePageStart(w, "tunn - "+title)
	fmt.Fprintf(w, `<div class="message success">%s</div>
<h1 class="page-title">%s</h1>
<p class="page-subtitle">%s</p>
`, message, title, message)
	fmt.Fprint(w, `<a href="/" class="btn btn-primary">Back to Home</a>`)
	writePageEnd(w)
}
