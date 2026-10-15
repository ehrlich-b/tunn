package host

import (
	"errors"
	"html/template"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

const accountEmailsPath = "/account/emails"

func (p *ProxyServer) handleAccountEmails(w http.ResponseWriter, r *http.Request) {
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
	claims, ok := p.accountSession(r)
	if !ok {
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(r.URL.RequestURI()), 302)
		return
	}
	account, err := p.sessionAccount(r, claims)
	if err != nil {
		http.Error(w, "Account service unavailable", 503)
		return
	}
	if account == nil {
		http.Error(w, "Sign in again to manage emails", 401)
		return
	}
	if account.OperationalState == "suspended" {
		http.Error(w, "Account suspended", 403)
		return
	}
	authority, ok := p.storage.(storage.AccountEmailStorage)
	if !ok {
		http.Error(w, "Account email service unavailable", 503)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if !p.requireCSRFToken(w, r, accountEmailsPath) {
			return
		}
	}
	raw := r.URL.Query().Get("token")
	if r.Method == http.MethodPost {
		raw = r.PostForm.Get("token")
	}
	if raw != "" {
		proof, valid := p.parseDomainToken(raw, "account_email_link")
		email, _ := proof["email"].(string)
		jti, _ := proof["jti"].(string)
		if !valid || proof["account_id"] != account.ID || !validGoogleEmail(email) || jti == "" {
			http.Error(w, "Invalid or expired link. Open it while signed in to the account that requested it.", 400)
			return
		}
		if r.Method == http.MethodGet {
			csrf, err := p.createCSRFToken(r, accountEmailsPath)
			if err != nil {
				http.Error(w, "Confirmation unavailable", 500)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			writePageStart(w, "Verify email - tunn")
			tmpl := template.Must(template.New("verify").Parse(`<h1 class="page-title">Verify email</h1><p>Add {{.Email}} to your account?</p><form method="POST" action="/account/emails"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="token" value="{{.Token}}"><button class="btn" type="submit">Verify and add email</button></form><p><a href="/account#emails">Cancel</a></p>`))
			_ = tmpl.Execute(w, struct{ Email, CSRF, Token string }{email, csrf, raw})
			writePageEnd(w)
			return
		}
		if _, err = p.verifyMailboxToken(r.Context(), raw, "account_email_link"); err != nil {
			http.Error(w, "Invalid or expired link", 400)
			return
		}
		_, err = authority.MutateAccountEmail(r.Context(), account.ID, email, "link")
	} else {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/account#emails", 303)
			return
		}
		email := common.NormalizeEmail(strings.TrimSpace(r.PostForm.Get("email")))
		parsed, parseErr := mail.ParseAddress(email)
		if !validGoogleEmail(email) || len(email) > 254 || parseErr != nil || parsed.Address != email {
			http.Error(w, "Invalid email address", 400)
			return
		}
		action := r.PostForm.Get("action")
		if action == "add" {
			owner, lookupErr := p.storage.GetAccountByEmail(r.Context(), email)
			if lookupErr != nil {
				http.Error(w, "Account service unavailable", 503)
				return
			}
			if owner != nil && owner.ID != account.ID {
				http.Error(w, store.ErrEmailOwned.Error(), 409)
				return
			}
			if owner != nil {
				http.Redirect(w, r, "/account#emails", 303)
				return
			}
			if p.emailSender == nil {
				http.Error(w, "Email delivery unavailable", 503)
				return
			}
			allowed, _, _, limitErr := p.storage.CheckMagicLinkRateLimit(r.Context(), email)
			if limitErr != nil {
				http.Error(w, "Email service unavailable", 503)
				return
			}
			if !allowed {
				http.Error(w, "Too many requests. Try again in a few minutes.", 429)
				return
			}
			token, signErr := p.generateMailboxToken(email, "", account.ID)
			if signErr != nil {
				http.Error(w, "Email service unavailable", 503)
				return
			}
			if err = p.emailSender.SendMagicLink(email, "https://"+p.config.PublicAddr+accountEmailsPath+"?token="+url.QueryEscape(token)); err != nil {
				http.Error(w, "Could not send email. Please retry.", 503)
				return
			}
			http.Redirect(w, r, "/account?email_sent=1#emails", 303)
			return
		}
		if action != "primary" {
			http.Error(w, "Invalid email action", 400)
			return
		}
		var updated *storage.Account
		updated, err = authority.MutateAccountEmail(r.Context(), account.ID, email, action)
		if err == nil {
			// This mailbox was verified by the account flow. Keep the account UUID and
			// record mailbox proof rather than attributing a new email to Google/GitHub.
			err = p.setAccountCookie(w, updated, updated.PrimaryEmail, "magic_link")
		}
	}
	if err != nil {
		if errors.Is(err, store.ErrEmailOwned) || errors.Is(err, store.ErrEmailNotLinked) {
			http.Error(w, err.Error(), 409)
			return
		}
		http.Error(w, "Account email update unavailable. Please retry.", 503)
		return
	}
	http.Redirect(w, r, "/account#emails", 303)
}
