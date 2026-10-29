// Package trafficpolicy defines bounded owner-configured HTTP request policies.
package trafficpolicy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const MaxJSONBytes = 16 * 1024

// Header edits apply in remove, rewrite, add order. Rewrite replaces all values;
// add appends a value. A field can appear in only one operation.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Headers struct {
	Remove  []string `json:"remove,omitempty"`
	Rewrite []Header `json:"rewrite,omitempty"`
	Add     []Header `json:"add,omitempty"`
}
type Limit struct {
	RequestsPerMinute int64 `json:"requests_per_minute"`
	Burst             int64 `json:"burst"`
}
type RateLimits struct {
	PerIP      *Limit `json:"per_ip,omitempty"`
	PerAccount *Limit `json:"per_account,omitempty"`
}
type Policy struct {
	Headers    Headers    `json:"headers"`
	RateLimits RateLimits `json:"rate_limits"`
	BasicAuth  *BasicAuth `json:"basic_auth,omitempty"`
}

// BasicAuth stores a bcrypt verifier, never the plaintext password.
type BasicAuth struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

var bcryptEncoding = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding).Strict()

// validBcryptHash validates the complete canonical verifier without doing an
// expensive password comparison. bcrypt.Cost only parses the version and cost.
func validBcryptHash(hash string) bool {
	if len(hash) != 60 || (hash[:4] != "$2a$" && hash[:4] != "$2b$" && hash[:4] != "$2y$") || hash[6] != '$' {
		return false
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil || cost < 10 || cost > 14 {
		return false
	}
	for _, part := range []string{hash[7:29], hash[29:]} {
		decoded, err := bcryptEncoding.DecodeString(part)
		if err != nil || bcryptEncoding.EncodeToString(decoded) != part {
			return false
		}
	}
	return true
}

func Decode(data []byte) (*Policy, error) {
	if len(data) > MaxJSONBytes || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, fmt.Errorf("policy must be a JSON object of at most %d bytes", MaxJSONBytes)
	}
	var p Policy
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid policy JSON: %w", err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("policy must contain one JSON object")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) Validate() error {
	if b := p.BasicAuth; b != nil {
		if len(b.Username) == 0 || len(b.Username) > 128 || b.Username == "tunn-app" || strings.ContainsAny(b.Username, ":\r\n\x00") {
			return fmt.Errorf("invalid basic auth username")
		}
		if !validBcryptHash(b.PasswordHash) {
			return fmt.Errorf("basic auth password_hash must be a bcrypt hash with cost 10..14")
		}
	}
	if len(p.Headers.Remove)+len(p.Headers.Rewrite)+len(p.Headers.Add) > 64 {
		return fmt.Errorf("at most 64 header edits are allowed")
	}
	seen := make(map[string]bool)
	check := func(name, value string) error {
		if len(name) == 0 || len(name) > 128 {
			return fmt.Errorf("invalid header name")
		}
		for _, c := range name {
			if c > 127 || !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return fmt.Errorf("invalid header name")
			}
		}
		lower := strings.ToLower(name)
		if protected(lower) {
			return fmt.Errorf("header %s is reserved", name)
		}
		if seen[lower] {
			return fmt.Errorf("header %s appears more than once", name)
		}
		seen[lower] = true
		if len(value) > 4096 {
			return fmt.Errorf("header value exceeds 4096 bytes")
		}
		for _, c := range []byte(value) {
			if c == 127 || c < 32 && c != '\t' {
				return fmt.Errorf("header value contains a control character")
			}
		}
		return nil
	}
	for i, name := range p.Headers.Remove {
		if err := check(name, ""); err != nil {
			return err
		}
		p.Headers.Remove[i] = http.CanonicalHeaderKey(name)
	}
	for _, edits := range [][]Header{p.Headers.Rewrite, p.Headers.Add} {
		for i := range edits {
			if err := check(edits[i].Name, edits[i].Value); err != nil {
				return err
			}
			edits[i].Name = http.CanonicalHeaderKey(edits[i].Name)
		}
	}
	for _, limit := range []*Limit{p.RateLimits.PerIP, p.RateLimits.PerAccount} {
		if limit != nil && (limit.RequestsPerMinute < 1 || limit.RequestsPerMinute > 1000000 || limit.Burst < 1 || limit.Burst > 10000) {
			return fmt.Errorf("rate limits require requests_per_minute in 1..1000000 and burst in 1..10000")
		}
	}
	data, err := json.Marshal(p)
	if err != nil || len(data) > MaxJSONBytes {
		return fmt.Errorf("policy exceeds %d bytes", MaxJSONBytes)
	}
	return nil
}

func protected(name string) bool {
	if strings.HasPrefix(name, "tunn-") || strings.HasPrefix(name, "x-tunn-") || strings.HasPrefix(name, "x-forwarded-") || strings.HasPrefix(name, "sec-websocket-") {
		return true
	}
	switch name {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "host", "content-length", "transfer-encoding", "connection", "proxy-connection", "keep-alive", "upgrade", "te", "trailer", "forwarded", "expect", "origin", "x-real-ip":
		return true
	}
	return false
}

// Apply clones the sanitized request, retaining credentials and relay-owned
// fields exactly as they were after authentication.
func (p *Policy) Apply(r *http.Request) *http.Request {
	out := r.Clone(r.Context())
	out.Header = r.Header.Clone()
	// Delete case-insensitively, including noncanonical maps from adapters.
	remove := func(name string) {
		for key := range out.Header {
			if strings.EqualFold(key, name) {
				delete(out.Header, key)
			}
		}
	}
	for _, name := range p.Headers.Remove {
		remove(name)
	}
	for _, edit := range p.Headers.Rewrite {
		remove(edit.Name)
		out.Header.Set(edit.Name, edit.Value)
	}
	for _, edit := range p.Headers.Add {
		for key, values := range out.Header {
			if key != edit.Name && strings.EqualFold(key, edit.Name) {
				out.Header[edit.Name] = append(out.Header[edit.Name], values...)
				delete(out.Header, key)
			}
		}
		out.Header.Add(edit.Name, edit.Value)
	}
	return out
}
