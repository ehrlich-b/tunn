package host

import (
	"fmt"
	"html"
	"html/template"
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
	switch message {
	case "Invalid Google login state", "Invalid login state", "Missing Google login binding", "Invalid Google login binding", "Missing Google authorization":
		message = "Sign-in expired or interrupted"
		detail = "Start sign-in again to continue."
	}
	writeBrowserError(w, status, browserErrorPage{Label: "Sign-in problem", Title: message, Detail: detail, Action: "Sign in again", Href: "/auth/login"}, authority)
}

type browserErrorPage struct {
	Label, Title, Detail, Action, Href, Command string
	Body                                        template.HTML // Only server-owned templates; user values are escaped first.
}

var browserErrorTemplate = template.Must(template.New("browser-error").Parse(`<section class="recovery" aria-labelledby="error-title"><span class="lbl">{{.Label}}</span><h1 id="error-title">{{.Title}}</h1><p>{{.Detail}}</p>{{.Body}}<div class="ctas">{{if .Command}}<code>{{.Command}}</code><button type="button" class="btn sig" data-copy="{{.Command}}" aria-describedby="copy-status">{{.Action}}</button><span id="copy-status" class="fine" role="status"></span>{{else}}<a class="btn sig" href="{{.Href}}">{{.Action}}</a>{{end}}</div></section>`))

// Shared product chrome and recovery hierarchy for browser-facing failures.
// The caller owns the HTTP status and supplies a reachable platform authority.
func writeBrowserError(w http.ResponseWriter, status int, data browserErrorPage, authority string) {
	var page strings.Builder
	writePageStart(&page, "tunn - "+html.EscapeString(data.Title))
	data.Label = fmt.Sprintf("%d · %s", status, data.Label)
	_ = browserErrorTemplate.Execute(&page, data)
	writePageEnd(&page)
	body := page.String()
	// An app-host denial must send recovery and asset requests to the login authority.
	if authority != "" {
		origin := "https://" + authority
		body = strings.ReplaceAll(body, `href="/`, `href="`+origin+`/`)
		body = strings.ReplaceAll(body, `src="/`, `src="`+origin+`/`)
		body = strings.ReplaceAll(body, "url(/assets/", "url("+origin+"/assets/")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, body)
}

func (p *ProxyServer) writeNotFound(w http.ResponseWriter, r *http.Request) {
	if !acceptsHTML(r) {
		http.NotFound(w, r)
		return
	}
	action, href := "Go home", "/"
	if _, ok := p.getAuthFromCookie(r); ok {
		action, href = "Go to account", "/account"
	}
	writeBrowserError(w, http.StatusNotFound, browserErrorPage{Label: "Page not found", Title: "This page could not be found", Detail: "Check the address or return to tunn.", Action: action, Href: href}, "")
}
