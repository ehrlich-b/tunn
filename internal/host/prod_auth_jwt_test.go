package host

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func prodAuthSigned(t *testing.T, p *ProxyServer, claims jwt.MapClaims, method jwt.SigningMethod, key any) string {
	t.Helper()
	if method == nil {
		method = jwt.SigningMethodHS256
	}
	if key == nil {
		key = p.getJWTSigningKey()
	}
	token, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// All account entry points must agree on the same signed claims. In particular,
// a login proof cannot substitute for a session and an identity must expire.
func TestProdAuthJWTValidationMatrix(t *testing.T) {
	p := securityProxy(nil)
	now := time.Now()
	cases := []struct {
		name   string
		modify func(jwt.MapClaims)
		method jwt.SigningMethod
		key    any
		allow  bool
	}{
		{name: "access", allow: true},
		{name: "session", modify: func(c jwt.MapClaims) { c["type"] = "session" }, allow: true},
		{name: "legacy-purpose", modify: func(c jwt.MapClaims) { delete(c, "type") }, allow: true},
		{name: "magic-link", modify: func(c jwt.MapClaims) { c["type"] = "magic_link" }},
		{name: "oauth-state", modify: func(c jwt.MapClaims) { c["type"] = "oauth_state" }},
		{name: "csrf", modify: func(c jwt.MapClaims) { c["type"] = "csrf" }},
		{name: "mcp-consent", modify: func(c jwt.MapClaims) { c["type"] = "mcp_consent" }},
		{name: "unknown-purpose", modify: func(c jwt.MapClaims) { c["type"] = "owner" }},
		{name: "null-purpose", modify: func(c jwt.MapClaims) { c["type"] = nil }},
		{name: "structured-purpose", modify: func(c jwt.MapClaims) { c["type"] = map[string]any{"session": true} }},
		{name: "missing-email", modify: func(c jwt.MapClaims) { delete(c, "email") }},
		{name: "empty-email", modify: func(c jwt.MapClaims) { c["email"] = "" }},
		{name: "non-string-email", modify: func(c jwt.MapClaims) { c["email"] = []string{"owner@example.com"} }},
		{name: "expired", modify: func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Minute).Unix() }},
		{name: "missing-expiry", modify: func(c jwt.MapClaims) { delete(c, "exp") }},
		{name: "zero-expiry", modify: func(c jwt.MapClaims) { c["exp"] = 0 }},
		{name: "null-expiry", modify: func(c jwt.MapClaims) { c["exp"] = nil }},
		{name: "string-expiry", modify: func(c jwt.MapClaims) { c["exp"] = "tomorrow" }},
		{name: "not-yet-valid", modify: func(c jwt.MapClaims) { c["nbf"] = now.Add(time.Hour).Unix() }},
		{name: "future-issued", modify: func(c jwt.MapClaims) { c["iat"] = now.Add(time.Hour).Unix() }},
		{name: "wrong-signature", key: []byte("other-signing-key")},
		{name: "unsigned", method: jwt.SigningMethodNone, key: jwt.UnsafeAllowNoneSignatureType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"type": "access", "email": "owner@example.com", "exp": now.Add(time.Hour).Unix()}
			if tc.modify != nil {
				tc.modify(claims)
			}
			token := prodAuthSigned(t, p, claims, tc.method, tc.key)
			for _, entry := range []string{"cookie", "bearer", "middleware", "publisher"} {
				t.Run(entry, func(t *testing.T) {
					r := httptest.NewRequest("GET", "https://tunn.test/account", nil)
					r.Header.Set("Authorization", "Bearer "+token)
					r.AddCookie(&http.Cookie{Name: authCookieName, Value: token})
					var allowed bool
					var email string
					var w *httptest.ResponseRecorder
					switch entry {
					case "cookie":
						email, allowed = p.getAuthFromCookie(r)
					case "bearer":
						email, _, _, allowed = p.getAuthFromTunnelBearer(r, &TunnelConnection{})
					case "middleware":
						w = httptest.NewRecorder()
						p.CheckJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							allowed = true
							w.WriteHeader(204)
						})).ServeHTTP(w, r)
					case "publisher":
						var err error
						email, err = p.tunnelServer.validateJWTAndExtractEmail(token)
						allowed = err == nil
					}
					if allowed != tc.allow {
						t.Errorf("authorization = %v, want %v", allowed, tc.allow)
					}
					if allowed && entry != "middleware" && email != "owner@example.com" {
						t.Errorf("identity = %q", email)
					}
					if w != nil && !tc.allow && w.Code != 401 {
						t.Errorf("denied middleware status = %d, want 401", w.Code)
					}
				})
			}
		})
	}
}
