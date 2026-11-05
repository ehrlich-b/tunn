package host

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/ehrlich-b/tunn/internal/storage"
)

const accountNamesPath = "/account/names"

func (p *ProxyServer) handleAccountNames(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Invalid account host", 403)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	// Keep the browser on the same origin; the login node validates session and CSRF.
	local, ok := p.storage.(*storage.LocalStorage)
	if !ok {
		p.loginNodeMu.RLock()
		addr := p.loginNodeHTTPAddr
		p.loginNodeMu.RUnlock()
		if addr != "" && r.Header.Get("Tunn-Names-Forwarded") == "" {
			clone := r.Clone(r.Context())
			clone.Header = r.Header.Clone()
			clone.Header.Set("Tunn-Names-Forwarded", "1")
			p.proxyToNode(w, clone, addr, "")
			return
		}
		http.Error(w, "Name service unavailable. Please retry.", 503)
		return
	}
	claims, ok := p.accountSession(r)
	if !ok {
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(accountNamesPath), 302)
		return
	}
	account, err := p.browserSessionAccount(w, r, claims)
	if err != nil {
		http.Error(w, "Account service unavailable", 503)
		return
	}
	if account == nil {
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(accountNamesPath), 302)
		return
	}
	if account.OperationalState != "active" {
		http.Error(w, "Account suspended", 403)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if !p.requireCSRFToken(w, r, accountNamesPath) {
			return
		}
	}

	message := ""
	status := http.StatusOK
	if r.Method == http.MethodPost {
		oldName := r.PostForm.Get("old_name")
		newName := strings.ToLower(strings.TrimSpace(r.PostForm.Get("new_name")))
		if r.PostForm.Get("confirm_name") != oldName || oldName == "" {
			message = "Type the exact old name to confirm its release."
		} else if !isValidDNSLabel(newName) || isReservedSubdomain(newName) || newName == oldName {
			message = "Choose a different available name: use letters, numbers or hyphens."
		} else if err = local.ReplaceAccountName(r.Context(), account.ID, oldName, newName); err != nil {
			message = "Could not replace this name. Stop both tunnels and choose an available name. Host-managed names must stay with their host. Your kept name is unchanged."
		} else {
			http.Redirect(w, r, accountNamesPath+"?replaced=1", 303)
			return
		}
		status = http.StatusConflict
	}
	names, err := local.AccountNames(r.Context(), account.ID)
	if err != nil {
		http.Error(w, "Names unavailable. Please retry.", 503)
		return
	}
	csrf, err := p.createCSRFToken(r, accountNamesPath)
	if err != nil {
		http.Error(w, "Name forms unavailable", 503)
		return
	}
	_, limit := planLimits(account.Plan)
	data := struct {
		Names       []storage.AccountName
		CSRF, Error string
		Limit, More int
		Replaced    bool
	}{names, csrf, message, limit, max(0, len(names)-4), r.URL.Query().Get("replaced") == "1"}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	writePageStart(w, "Kept names - tunn")
	_ = accountNamesTemplate.Execute(w, data)
	writePageEnd(w)
}

var accountNamesTemplate = template.Must(template.New("names").Funcs(template.FuncMap{"nameRow": func(row storage.AccountName, csrf string) any {
	return struct {
		Row  storage.AccountName
		CSRF string
	}{row, csrf}
}}).Parse(`
<style>.name-list{list-style:none;padding:0;margin:16px 0}.name-row{padding:12px 0;border-top:1px solid var(--plate-lo);overflow-wrap:anywhere}.name-head{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}.name-row form{display:grid;gap:10px;max-width:440px;margin:12px 0}.name-row label{display:grid;gap:4px}.name-row input{box-sizing:border-box;min-width:0;width:100%;padding:10px;font:inherit;color:var(--ink);background:var(--plate-hi);border:1px solid var(--plate-lo);border-radius:4px}.name-row button{justify-self:start}.name-row summary{cursor:pointer;margin-top:8px}.name-state{font-size:13px;color:var(--ink2)}.name-more>summary{cursor:pointer}.name-error{padding:12px;border:1px solid var(--warn);overflow-wrap:anywhere}</style>
<p><a href="/account">← Account</a></p><h1 class="page-title">Kept names</h1>
<p>Your plan keeps {{.Limit}} name{{if ne .Limit 1}}s{{end}}. Temporary names last only while connected.</p>
<p>Replacing a kept name releases the old name: someone else can claim it. Stop both tunnels first. Existing links are never renamed.</p>
{{if .Error}}<p class="name-error" role="alert">{{.Error}}</p>{{end}}
{{if .Replaced}}<p role="status">Kept name replaced. Start your next tunnel with <code>--name</code> and the new name.</p>{{end}}
{{define "row"}}<li class="name-row"><div class="name-head"><strong>{{.Row.Name}}</strong><span class="name-state">{{if .Row.Kept}}Kept{{else}}Temporary{{end}} · {{if .Row.Active}}Connected{{else}}Offline{{end}}</span></div>
{{if .Row.Kept}}<details><summary>Replace name</summary><form method="post" action="/account/names"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="old_name" value="{{.Row.Name}}"><label>New name<input name="new_name" maxlength="63" pattern="[a-z0-9][a-z0-9-]*" required autocomplete="off"></label><label>Type {{.Row.Name}} to release it<input name="confirm_name" required autocomplete="off" spellcheck="false"></label><span class="fine">Someone else can claim {{.Row.Name}} after replacement.</span><button class="btn" type="submit">Release and replace</button></form></details>{{end}}</li>{{end}}
<ul class="name-list">{{range $i,$row:=.Names}}{{if lt $i 4}}{{template "row" (nameRow $row $.CSRF)}}{{end}}{{else}}<li>No kept or connected names yet. Your first available tunnel name is kept automatically.</li>{{end}}</ul>
{{if .More}}<details class="name-more"><summary>+{{.More}} more</summary><ul class="name-list">{{range $i,$row:=.Names}}{{if ge $i 4}}{{template "row" (nameRow $row $.CSRF)}}{{end}}{{end}}</ul></details>{{end}}
`))
