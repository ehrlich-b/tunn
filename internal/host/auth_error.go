package host

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

// writeAuthError keeps machine responses plain and gives browser users a way back.
func (p *ProxyServer) writeAuthError(w http.ResponseWriter, r *http.Request, message string, status int, detail string) {
	origin := ""
	if !p.isPlatformHost(r.Host) {
		origin = p.loginAuthority()
	}
	writeBrowserAuthError(w, r, message, status, detail, origin)
}

func writeBrowserAuthError(w http.ResponseWriter, r *http.Request, message string, status int, detail, authority string) {
	if !acceptsHTML(r) {
		http.Error(w, message, status)
		return
	}
	var page strings.Builder
	writePageStart(&page, "tunn - "+html.EscapeString(message))
	_, _ = fmt.Fprintf(&page, `<section class="recovery"><span class="lbl">%d · Sign-in problem</span><h1>%s</h1><p>%s</p><div class="ctas"><a class="btn sig" href="/auth/login">Sign in again</a><a class="btn" href="/auth/logout">Sign out</a></div></section>`, status, html.EscapeString(message), html.EscapeString(detail))
	writePageEnd(&page)
	body := page.String()
	// An app-host denial must send recovery and asset requests to the login authority.
	if authority != "" {
		origin := "https://" + authority
		body = strings.ReplaceAll(body, `href="/`, `href="`+origin+`/`)
		body = strings.ReplaceAll(body, `src="/`, `src="`+origin+`/`)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, body)
}
