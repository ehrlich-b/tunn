package common

import (
	"net/mail"
	"strings"
)

const GoogleIssuer = "https://accounts.google.com"

// GoogleAuthoritativeEmail excludes historically verified third-party mailboxes.
// Workspace admission also binds the hosted domain to the claimed email domain.
func GoogleAuthoritativeEmail(email, hostedDomain string, verified bool) bool {
	if !verified || strings.TrimSpace(email) != email {
		return false
	}
	for _, c := range email {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || strings.Count(email, "@") != 1 {
		return false
	}
	domain := strings.ToLower(strings.SplitN(email, "@", 2)[1])
	return domain == "gmail.com" || hostedDomain != "" && strings.EqualFold(hostedDomain, domain) && strings.Contains(domain, ".")
}
