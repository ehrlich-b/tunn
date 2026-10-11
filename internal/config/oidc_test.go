package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validOIDCOrg() OIDCOrg {
	return OIDCOrg{ID: "acme", Name: "Acme", Provider: "okta", Issuer: "https://acme.okta.com/oauth2/default", ClientID: "client", ClientSecret: "secret", AllowedDomains: []string{"acme.test"}, Groups: []OIDCGroup{{ID: "engineering", Name: "Engineering", Claim: "groups", Value: "Engineering"}}}
}

func TestOIDCConfigPrivateFileAndGoogleCredentialReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orgs.json")
	org := validOIDCOrg()
	org.Provider, org.Issuer, org.ClientID, org.ClientSecret, org.Groups = "google", "https://accounts.google.com", "", "", nil
	data, _ := json.Marshal([]OIDCOrg{org})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{GoogleClientID: "consumer-client", GoogleClientSecret: "consumer-secret"}
	if err := cfg.loadOIDCOrgs(path); err != nil || cfg.OIDCOrgs[0].ClientID != "consumer-client" {
		t.Fatal("Google credentials not reused", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := cfg.loadOIDCOrgs(path); err == nil {
		t.Fatal("publicly readable org secret accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`[{"id":"acme","unknown_secret":"do-not-print"}]`, string(data) + " {}", `null`, strings.Repeat("x", (1<<20)+1)} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		err := cfg.loadOIDCOrgs(path)
		// null/empty is an intentional way to disable org sign-in.
		if body != "null" && (err == nil || strings.Contains(err.Error(), "do-not-print")) {
			t.Fatal("invalid config accepted or secret disclosed", err)
		}
	}
}

func TestOIDCConfigValidationAndGroupNamespace(t *testing.T) {
	valid := validOIDCOrg()
	if err := (&Config{OIDCOrgs: []OIDCOrg{valid}}).ValidateOIDCOrgs(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*OIDCOrg){
		"http issuer":               func(o *OIDCOrg) { o.Issuer = "http://acme.okta.com" },
		"issuer userinfo":           func(o *OIDCOrg) { o.Issuer = "https://client:secret@acme.okta.com" },
		"issuer query":              func(o *OIDCOrg) { o.Issuer += "?issuer=other" },
		"trailing issuer slash":     func(o *OIDCOrg) { o.Issuer += "/" },
		"common entra tenant":       func(o *OIDCOrg) { o.Provider, o.Issuer = "entra", "https://login.microsoftonline.com/common/v2.0" },
		"google lookalike":          func(o *OIDCOrg) { o.Provider, o.Issuer = "google", "https://accounts.google.com.evil.test" },
		"gmail org":                 func(o *OIDCOrg) { o.AllowedDomains = []string{"gmail.com"} },
		"domain wildcard":           func(o *OIDCOrg) { o.AllowedDomains = []string{"*.acme.test"} },
		"empty domains":             func(o *OIDCOrg) { o.AllowedDomains = nil },
		"missing secret":            func(o *OIDCOrg) { o.ClientSecret = "" },
		"secret newline":            func(o *OIDCOrg) { o.ClientSecret = "secret\nvalue" },
		"google delegation missing": func(o *OIDCOrg) { o.Provider, o.Issuer = "google", "https://accounts.google.com" },
		"unsupported provider":      func(o *OIDCOrg) { o.Provider = "saml" },
		"group uppercase":           func(o *OIDCOrg) { o.Groups[0].ID = "Engineering" },
		"role on okta":              func(o *OIDCOrg) { o.Groups[0].Claim = "roles" },
		"group missing claim":       func(o *OIDCOrg) { o.Groups[0].Claim = "" },
		"duplicate group":           func(o *OIDCOrg) { o.Groups = append(o.Groups, o.Groups[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			o := validOIDCOrg()
			mutate(&o)
			if err := (&Config{OIDCOrgs: []OIDCOrg{o}}).ValidateOIDCOrgs(); err == nil {
				t.Fatal("invalid organization config accepted")
			}
		})
	}
	if err := (&Config{OIDCOrgs: []OIDCOrg{valid, valid}}).ValidateOIDCOrgs(); err == nil {
		t.Fatal("duplicate org allowed")
	}
	if err := (&Config{PublicMode: true, OIDCOrgs: []OIDCOrg{valid}}).ValidateOIDCOrgs(); err == nil {
		t.Fatal("public-mode org allowed")
	}
	org := validOIDCOrg()
	org.Provider, org.Issuer = "entra", "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
	org.Groups[0].Claim = "roles"
	cfg := &Config{OIDCOrgs: []OIDCOrg{org}}
	if err := cfg.ValidateOIDCOrgs(); err != nil || !cfg.OIDCGroupExists("group:acme:engineering") || cfg.OIDCGroupExists("group:other:engineering") {
		t.Fatal("tenant/group validation failed", err)
	}
	for _, bad := range []string{"engineering", "group:acme", "group:acme:engineering:extra", "group:Acme:engineering", "group:acme:eng\n", "group:acme:*", "person:alice@acme.test"} {
		if ValidOIDCGroupSubject(bad) {
			t.Fatalf("invalid namespace %q", bad)
		}
	}
	before := org.PolicyDigest()
	org.Groups[0].Value = "DifferentRole"
	if before == org.PolicyDigest() {
		t.Fatal("group remapping retained sessions")
	}
}
