package trafficpolicy

import (
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPolicyHeaderOperations(t *testing.T) {
	p, err := Decode([]byte(`{"headers":{"remove":["x-remove"],"rewrite":[{"name":"x-rewrite","value":"new"}],"add":[{"name":"x-add","value":"extra"}]},"rate_limits":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://example.test/", nil)
	r.Header["x-remove"] = []string{"gone"}
	r.Header["X-Rewrite"] = []string{"old", "older"}
	r.Header["x-add"] = []string{"first"}
	r.Header.Set("Authorization", "Bearer application")
	r.Header.Set("X-Tunn-Identity", "relay")
	out := p.Apply(r)
	if out.Header.Get("X-Remove") != "" || out.Header.Get("X-Rewrite") != "new" || strings.Join(out.Header.Values("X-Add"), ",") != "first,extra" {
		t.Fatalf("edits: %v", out.Header)
	}
	if out.Header.Get("Authorization") != "Bearer application" || out.Header.Get("X-Tunn-Identity") != "relay" {
		t.Fatal("protected fields changed")
	}
	if r.Header.Get("X-Rewrite") != "old" || r.Header["x-remove"][0] != "gone" {
		t.Fatal("input request changed")
	}
}

func TestBasicAuthPolicyValidation(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("fixture password"), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		user, hash string
		valid      bool
	}{
		{"demo", string(hash), true}, {"", string(hash), false}, {"a:b", string(hash), false},
		{"demo", "plaintext", false}, {"demo", "$2a$04$" + strings.Repeat("x", 53), false},
		{"demo", "$2a$15$" + strings.Repeat("x", 53), false},
	} {
		err := (&Policy{BasicAuth: &BasicAuth{Username: tc.user, PasswordHash: tc.hash}}).Validate()
		if (err == nil) != tc.valid {
			t.Errorf("user=%q hash=%q error=%v", tc.user, tc.hash, err)
		}
	}
}

func TestPolicyValidationRejectsUnsafeHeadersAndJSON(t *testing.T) {
	for _, name := range []string{"Authorization", "Cookie", "Host", "Content-Length", "Transfer-Encoding", "Connection", "Trailer", "Upgrade", "X-Forwarded-For", "Forwarded", "X-Real-IP", "X-Tunn-Identity", "Tunn-Authorization", "Sec-WebSocket-Key", "Origin", "invalid name", "Bad:Name", "é"} {
		t.Run(name, func(t *testing.T) {
			if err := (&Policy{Headers: Headers{Remove: []string{name}}}).Validate(); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
	for _, data := range []string{`null`, `[]`, `{} {}`, `{"unknown":true}`, `{"headers":{"add":[{"name":"X-Test","value":"a\r\nb"}]}}`, `{"headers":{"remove":["x-test"],"add":[{"name":"X-Test","value":"a"}]}}`, `{"rate_limits":{"per_ip":{"requests_per_minute":0,"burst":1}}}`, `{"rate_limits":{"per_account":{"requests_per_minute":1,"burst":10001}}}`} {
		if _, err := Decode([]byte(data)); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
	if _, err := Decode([]byte(strings.Repeat(" ", MaxJSONBytes+1))); err == nil {
		t.Fatal("accepted oversized JSON")
	}
}
