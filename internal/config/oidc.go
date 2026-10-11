package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const MaxOIDCOrgs = 32
const MaxOIDCGroups = 16 // Keep signed browser sessions below cookie size limits.

type OIDCGroup struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Claim string `json:"claim"` // groups, or Entra application roles
	Value string `json:"value"` // exact provider group name/object ID or role
}

type OIDCOrg struct {
	ID                    string      `json:"id"`
	Name                  string      `json:"name"`
	Provider              string      `json:"provider"` // okta, entra, google
	Issuer                string      `json:"issuer"`
	ClientID              string      `json:"client_id"`
	ClientSecret          string      `json:"client_secret"`
	AllowedDomains        []string    `json:"allowed_domains"`
	Groups                []OIDCGroup `json:"groups"`
	GoogleCredentialsFile string      `json:"google_credentials_file,omitempty"`
	GoogleDirectoryAdmin  string      `json:"google_directory_admin,omitempty"`
}

var oidcSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var entraTenant = regexp.MustCompile(`^/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/v2\.0$`)

// PolicyDigest invalidates browser sessions on any org configuration change,
// including a replaced issuer/client or a group alias remapped to a new ID.
func (o OIDCOrg) PolicyDigest() string {
	data, _ := json.Marshal(o)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (o OIDCOrg) AllowsDomain(domain string) bool {
	for _, c := range domain {
		if c > 127 || c <= 32 {
			return false
		}
	}
	for _, allowed := range o.AllowedDomains {
		if strings.EqualFold(domain, allowed) {
			return true
		}
	}
	return false
}

func ValidOIDCGroupSubject(subject string) bool {
	parts := strings.Split(subject, ":")
	return len(parts) == 3 && parts[0] == "group" && oidcSlug.MatchString(parts[1]) && oidcSlug.MatchString(parts[2])
}

func (c *Config) OIDCOrg(id string) (OIDCOrg, bool) {
	for _, org := range c.OIDCOrgs {
		if org.ID == id {
			return org, true
		}
	}
	return OIDCOrg{}, false
}

func (c *Config) OIDCGroupExists(subject string) bool {
	if !ValidOIDCGroupSubject(subject) {
		return false
	}
	parts := strings.Split(subject, ":")
	org, found := c.OIDCOrg(parts[1])
	if !found {
		return false
	}
	for _, group := range org.Groups {
		if group.ID == parts[2] {
			return true
		}
	}
	return false
}

// ReadPrivateOIDCFile bounds secret files and refuses permissions that make
// client secrets or delegated signing keys readable by another local user.
func ReadPrivateOIDCFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open organization credentials file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("organization credentials require a regular file of at most 1 MiB with mode 0600 or 0400")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, fmt.Errorf("cannot read organization credentials file")
	}
	return data, nil
}

func (c *Config) loadOIDCOrgs(path string) error {
	if path == "" {
		return nil
	}
	data, err := ReadPrivateOIDCFile(path)
	if err != nil {
		return fmt.Errorf("TUNN_OIDC_ORGS_FILE: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&c.OIDCOrgs); err != nil {
		return fmt.Errorf("TUNN_OIDC_ORGS_FILE must be an organization JSON array")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return fmt.Errorf("TUNN_OIDC_ORGS_FILE has trailing data")
	}
	for i := range c.OIDCOrgs {
		o := &c.OIDCOrgs[i]
		if o.Provider == "google" && o.ClientID == "" && o.ClientSecret == "" {
			o.ClientID, o.ClientSecret = c.GoogleClientID, c.GoogleClientSecret
		}
	}
	return c.ValidateOIDCOrgs()
}

func (c *Config) ValidateOIDCOrgs() error {
	if len(c.OIDCOrgs) > MaxOIDCOrgs || len(c.OIDCOrgs) > 0 && c.PublicMode {
		return fmt.Errorf("organization sign-in requires authenticated mode and at most %d organizations", MaxOIDCOrgs)
	}
	seen := map[string]bool{}
	for _, o := range c.OIDCOrgs {
		if !oidcSlug.MatchString(o.ID) || seen[o.ID] || !validOIDCText(o.Name, 80) || !validOIDCText(o.ClientID, 512) || !validOIDCText(o.ClientSecret, 4096) {
			return fmt.Errorf("invalid or duplicate organization ID, name or client credentials")
		}
		seen[o.ID] = true
		u, err := url.Parse(o.Issuer)
		if err != nil || u.Scheme != "https" || !validHost(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.HasSuffix(o.Issuer, "/") {
			return fmt.Errorf("organization %s requires an exact HTTPS issuer without query, credentials or trailing slash", o.ID)
		}
		switch o.Provider {
		case "okta":
		case "entra":
			if !entraTenant.MatchString(u.Path) {
				return fmt.Errorf("organization %s requires a tenant UUID v2.0 issuer, never common or organizations", o.ID)
			}
		case "google":
			if o.Issuer != "https://accounts.google.com" {
				return fmt.Errorf("organization %s requires the Google accounts issuer", o.ID)
			}
		default:
			return fmt.Errorf("organization %s provider must be okta, entra or google", o.ID)
		}
		if len(o.AllowedDomains) == 0 || len(o.AllowedDomains) > 32 || len(o.Groups) > MaxOIDCGroups {
			return fmt.Errorf("organization %s requires allowed domains and at most %d group mappings", o.ID, MaxOIDCGroups)
		}
		domains := map[string]bool{}
		for _, d := range o.AllowedDomains {
			if !validHost(d) || !strings.Contains(d, ".") || strings.ToLower(d) != d || domains[d] || d == "gmail.com" || d == "googlemail.com" || strings.ContainsAny(d, "*:@/") {
				return fmt.Errorf("organization %s requires unique exact company domains", o.ID)
			}
			domains[d] = true
		}
		groups := map[string]bool{}
		for _, g := range o.Groups {
			if !oidcSlug.MatchString(g.ID) || groups[g.ID] || !validOIDCText(g.Name, 80) || !validOIDCText(g.Value, 256) || g.Claim != "groups" && (g.Claim != "roles" || o.Provider != "entra") {
				return fmt.Errorf("organization %s has invalid or duplicate group mappings", o.ID)
			}
			groups[g.ID] = true
		}
		if o.Provider == "google" && len(o.Groups) > 0 {
			admin, err := mail.ParseAddress(o.GoogleDirectoryAdmin)
			if o.GoogleCredentialsFile == "" || err != nil || admin.Address != o.GoogleDirectoryAdmin || !o.AllowsDomain(strings.Split(o.GoogleDirectoryAdmin, "@")[1]) {
				return fmt.Errorf("organization %s group lookup requires delegated credentials and a company Directory administrator", o.ID)
			}
		} else if o.GoogleCredentialsFile != "" || o.GoogleDirectoryAdmin != "" {
			return fmt.Errorf("organization %s has unused Google delegation credentials", o.ID)
		}
	}
	return nil
}

func validOIDCText(s string, max int) bool {
	return s != "" && len(s) <= max && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
