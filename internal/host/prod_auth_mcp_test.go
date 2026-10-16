package host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func prodAuthOAuthError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var problem struct {
		Error string `json:"error"`
	}
	if w.Code != status || json.Unmarshal(w.Body.Bytes(), &problem) != nil || problem.Error != code {
		t.Fatalf("OAuth response = %d %s, want %d %s", w.Code, w.Body, status, code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("OAuth response is cacheable")
	}
}

func TestProdAuthMCPOAuthMetadataContract(t *testing.T) {
	f := newMCPOAuthFixture(t)
	f.p.config.PublicAddr = "tunn.test:8443"
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		w := f.request("GET", "https://tools.tunn.test:8443"+path, "", "", "", nil)
		var got struct {
			Resource string   `json:"resource"`
			Servers  []string `json:"authorization_servers"`
			Scopes   []string `json:"scopes_supported"`
			Methods  []string `json:"bearer_methods_supported"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Resource != "https://tools.tunn.test:8443/mcp" || len(got.Servers) != 1 || got.Servers[0] != "https://tunn.test:8443" || strings.Join(got.Scopes, ",") != "mcp" || strings.Join(got.Methods, ",") != "header" {
			t.Fatalf("resource metadata: %d %s", w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
			t.Fatal("resource metadata has incorrect caching or content type")
		}
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			denied := f.request(method, "https://tools.tunn.test:8443"+path, "", "", "", nil)
			if denied.Code != 405 || denied.Header().Get("Allow") != "GET" {
				t.Fatalf("metadata method %s: %d %s", method, denied.Code, denied.Header())
			}
		}
	}
	issuer := "https://tunn.test:8443"
	w := f.request("GET", issuer+"/.well-known/oauth-authorization-server", "", "", "", nil)
	var metadata map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &metadata) != nil {
		t.Fatalf("authorization metadata: %d %s", w.Code, w.Body)
	}
	for key, expected := range map[string]string{
		"issuer": issuer, "authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint": issuer + "/oauth/token", "registration_endpoint": issuer + "/oauth/register",
	} {
		var value string
		if json.Unmarshal(metadata[key], &value) != nil || value != expected {
			t.Errorf("%s = %s, want %q", key, metadata[key], expected)
		}
	}
	for key, expected := range map[string]string{
		"response_types_supported": "code", "grant_types_supported": "authorization_code,refresh_token",
		"token_endpoint_auth_methods_supported": "none", "code_challenge_methods_supported": "S256", "scopes_supported": "mcp",
	} {
		var value []string
		if json.Unmarshal(metadata[key], &value) != nil || strings.Join(value, ",") != expected {
			t.Errorf("%s = %s, want [%q]", key, metadata[key], expected)
		}
	}
	var issuerParameter bool
	if json.Unmarshal(metadata["authorization_response_iss_parameter_supported"], &issuerParameter) != nil || !issuerParameter {
		t.Error("authorization response issuer binding was not advertised")
	}
}

func TestProdAuthMCPOAuthRegistrationRedirectMatrix(t *testing.T) {
	cases := []struct {
		uri   string
		allow bool
	}{
		{"https://connector.example/cb", true},
		{"https://connector.example:8443/cb?tenant=one", true},
		{"http://127.0.0.1:1234/cb", true},
		{"http://127.0.0.2:1234/cb", true},
		{"http://[::1]:1234/cb", true},
		{"http://localhost:1234/cb", false},
		{"http://192.0.2.1/cb", false},
		{"http://connector.example/cb", false},
		{"https://user@connector.example/cb", false},
		{"https://connector.example/cb#part", false},
		{"https:///cb", false},
		{"/cb", false},
		{"javascript:callback()", false},
		{"https://connector.example:invalid/cb", false},
	}
	for _, tc := range cases {
		t.Run(tc.uri, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			body, err := json.Marshal(map[string]any{"redirect_uris": []string{tc.uri}})
			if err != nil {
				t.Fatal(err)
			}
			w := f.request("POST", "https://tunn.test/oauth/register", string(body), "application/json", "", nil)
			if !tc.allow {
				prodAuthOAuthError(t, w, 400, "invalid_redirect_uri")
				return
			}
			var client mcpOAuthClient
			if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &client) != nil || client.AuthMethod != "none" || len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != tc.uri || client.ID == "" || client.IssuedAt == 0 {
				t.Fatalf("registered client: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestProdAuthMCPOAuthClientMetadataMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, body, problem string
	}{
		{"missing-redirect", `{}`, "invalid_redirect_uri"},
		{"empty-redirects", `{"redirect_uris":[]}`, "invalid_redirect_uri"},
		{"client-authentication", `{"redirect_uris":["https://connector.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`, "invalid_client_metadata"},
		{"unsupported-grant", `{"redirect_uris":["https://connector.example/cb"],"grant_types":["authorization_code","password"]}`, "invalid_client_metadata"},
		{"implicit-response", `{"redirect_uris":["https://connector.example/cb"],"response_types":["token"]}`, "invalid_client_metadata"},
		{"second-object", `{"redirect_uris":["https://connector.example/cb"]} {}`, "invalid_client_metadata"},
		{"array", `[]`, "invalid_client_metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			w := f.request("POST", "https://tunn.test/oauth/register", tc.body, "application/json", "", nil)
			prodAuthOAuthError(t, w, 400, tc.problem)
			var count int
			if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM mcp_oauth_clients`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("invalid metadata created a client: count %d, error %v", count, err)
			}
		})
	}
	for _, redirects := range []int{10, 11} {
		f := newMCPOAuthFixture(t)
		uris := make([]string, redirects)
		for i := range uris {
			uris[i] = "https://connector.example/cb?tenant=" + strconv.Itoa(i)
		}
		body, err := json.Marshal(map[string]any{"redirect_uris": uris, "client_id": "supplied-client-id", "client_id_issued_at": 1})
		if err != nil {
			t.Fatal(err)
		}
		w := f.request("POST", "https://tunn.test/oauth/register", string(body), "application/json", "", nil)
		if redirects == 11 {
			prodAuthOAuthError(t, w, 400, "invalid_redirect_uri")
			continue
		}
		var client mcpOAuthClient
		if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &client) != nil || client.ID == "supplied-client-id" || client.IssuedAt == 1 || len(client.RedirectURIs) != 10 {
			t.Fatalf("server-issued registration metadata: %d %s", w.Code, w.Body)
		}
	}
}

func TestProdAuthMCPOAuthPKCEVerifierMatrix(t *testing.T) {
	cases := []struct {
		name, verifier string
		allow          bool
	}{
		{"minimum", strings.Repeat("a", 43), true},
		{"maximum", strings.Repeat("a", 128), true},
		{"unreserved", strings.Repeat("A0-._~", 8), true},
		{"short", strings.Repeat("a", 42), false},
		{"long", strings.Repeat("a", 129), false},
		{"space", strings.Repeat("a", 42) + " ", false},
		{"plus", strings.Repeat("a", 42) + "+", false},
		{"slash", strings.Repeat("a", 42) + "/", false},
		{"equals", strings.Repeat("a", 42) + "=", false},
		{"unicode", strings.Repeat("a", 42) + "é", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			c := discoverMCPClient(t, f)
			if tc.allow {
				c.verifier = tc.verifier
				hash := sha256.Sum256([]byte(c.verifier))
				c.query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(hash[:]))
			}
			code := c.code(t)
			form := c.tokenForm(code)
			form.Set("code_verifier", tc.verifier)
			w := f.request("POST", c.token, form.Encode(), "application/x-www-form-urlencoded", "", nil)
			if tc.allow {
				if w.Code != 200 {
					t.Fatalf("valid verifier failed: %d %s", w.Code, w.Body)
				}
				return
			}
			prodAuthOAuthError(t, w, 400, "invalid_grant")
			// Validation failures cannot consume a still-valid code.
			if w := f.request("POST", c.token, c.tokenForm(code).Encode(), "application/x-www-form-urlencoded", "", nil); w.Code != 200 {
				t.Fatalf("invalid verifier consumed code: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestProdAuthMCPOAuthParameterMatrix(t *testing.T) {
	for _, stage := range []string{"authorize", "token"} {
		for _, failure := range []string{"duplicate-client", "duplicate-resource", "unsupported-flow", "wrong-resource", "wrong-redirect", "wrong-scope-or-secret"} {
			t.Run(stage+"/"+failure, func(t *testing.T) {
				f := newMCPOAuthFixture(t)
				c := discoverMCPClient(t, f)
				c.login(t)
				form := c.query
				code := ""
				if stage == "token" {
					code = c.code(t)
					form = c.tokenForm(code)
				}
				problem, redirect := "invalid_request", false
				switch failure {
				case "duplicate-client":
					form.Add("client_id", c.clientID)
				case "duplicate-resource":
					form.Add("resource", c.resource)
				case "unsupported-flow":
					if stage == "token" {
						form.Set("grant_type", "password")
						problem = "unsupported_grant_type"
					} else {
						form.Set("response_type", "token")
						problem, redirect = "unsupported_response_type", true
					}
				case "wrong-resource":
					form.Set("resource", c.resource+"?variant=1")
					if stage == "token" {
						problem = "invalid_grant"
					} else {
						problem, redirect = "invalid_target", true
					}
				case "wrong-redirect":
					form.Set("redirect_uri", c.redirect+"/other")
					if stage == "token" {
						problem = "invalid_grant"
					}
				case "wrong-scope-or-secret":
					if stage == "token" {
						form.Set("client_secret", "unused")
						problem = "invalid_client"
					} else {
						form.Set("scope", "mcp account")
						problem, redirect = "invalid_scope", true
					}
				}
				var w *httptest.ResponseRecorder
				if stage == "token" {
					w = f.request("POST", c.token, form.Encode(), "application/x-www-form-urlencoded", "", nil)
				} else {
					w = f.request("GET", c.authorize+"?"+form.Encode(), "", "", "", c.cookie)
				}
				if redirect {
					location, err := url.Parse(w.Header().Get("Location"))
					if err != nil || w.Code != 302 || location.Scheme+"://"+location.Host+location.Path != c.redirect || location.Query().Get("error") != problem || location.Query().Get("state") != c.query.Get("state") || location.Query().Get("iss") != "https://tunn.test" {
						t.Fatalf("OAuth redirect: %d %s", w.Code, w.Header())
					}
				} else {
					prodAuthOAuthError(t, w, 400, problem)
					if w.Header().Get("Location") != "" {
						t.Fatal("invalid binding produced a redirect")
					}
				}
			})
		}
	}
}

func TestProdAuthMCPOAuthContentTypes(t *testing.T) {
	for _, endpoint := range []string{"register", "token"} {
		for _, suffix := range []string{"", "; charset=utf-8", "-other", "; broken"} {
			t.Run(endpoint+suffix, func(t *testing.T) {
				f := newMCPOAuthFixture(t)
				c := discoverMCPClient(t, f)
				contentType, body, target, status := "application/json", `{"redirect_uris":["https://connector.example/cb"]}`, "https://tunn.test/oauth/register", 201
				if endpoint == "token" {
					contentType, body, target, status = "application/x-www-form-urlencoded", c.tokenForm(c.code(t)).Encode(), c.token, 200
				}
				w := f.request("POST", target, body, contentType+suffix, "", nil)
				if suffix == "-other" || suffix == "; broken" {
					status = 400
					problem := "invalid_client_metadata"
					if endpoint == "token" {
						problem = "invalid_request"
					}
					prodAuthOAuthError(t, w, status, problem)
				}
				if w.Code != status {
					t.Fatalf("media type %q returned %d, want %d: %s", contentType+suffix, w.Code, status, w.Body)
				}
			})
		}
	}
}

func TestProdAuthMCPOAuthOwnershipAndExpiry(t *testing.T) {
	for _, stage := range []string{"consent", "exchange"} {
		for _, change := range []string{"expired", "owner-changed", "offline"} {
			t.Run(stage+"/"+change, func(t *testing.T) {
				f := newMCPOAuthFixture(t)
				c := discoverMCPClient(t, f)
				form := c.consentForm(t)
				code := ""
				if stage == "exchange" {
					code = c.code(t)
				}
				switch change {
				case "expired":
					query, value := `UPDATE mcp_oauth_consents SET expires=?`, any(nil)
					if stage == "exchange" {
						query = `UPDATE mcp_oauth_codes SET expires=?`
					}
					value = time.Now().Add(-time.Minute).Unix()
					if _, err := f.p.mcpOAuth.db.Exec(query, value); err != nil {
						t.Fatal(err)
					}
				case "owner-changed":
					other, err := f.p.storage.FindOrCreateByEmails(context.Background(), []string{"other@example.com"}, "test")
					if err != nil {
						t.Fatal(err)
					}
					f.tunnel.AccountID, f.tunnel.CreatorEmail = other.ID, "other@example.com"
				case "offline":
					delete(f.p.tunnelServer.tunnels, "tools")
				}
				if stage == "exchange" {
					w := f.request("POST", c.token, c.tokenForm(code).Encode(), "application/x-www-form-urlencoded", "", nil)
					prodAuthOAuthError(t, w, 400, "invalid_grant")
				} else {
					w := f.request("POST", c.authorize, form.Encode(), "application/x-www-form-urlencoded", "", c.cookie)
					if change == "expired" {
						prodAuthOAuthError(t, w, 503, "temporarily_unavailable")
					} else {
						location, err := url.Parse(w.Header().Get("Location"))
						if err != nil || w.Code != 302 || location.Query().Get("error") != "access_denied" || location.Query().Get("code") != "" {
							t.Fatalf("stale consent: %d %s", w.Code, w.Header())
						}
					}
				}
			})
		}
	}
}

func TestProdAuthOAuthStateLifetimeAndPurpose(t *testing.T) {
	p := securityProxy(nil)
	for _, change := range []string{"valid", "missing-expiry", "zero-expiry", "expired", "wrong-purpose", "missing-state"} {
		t.Run(change, func(t *testing.T) {
			claims := jwt.MapClaims{"type": "oauth_state", "state": "browser-state", "return_to": "/account", "exp": time.Now().Add(time.Minute).Unix()}
			switch change {
			case "missing-expiry":
				delete(claims, "exp")
			case "zero-expiry":
				claims["exp"] = 0
			case "expired":
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			case "wrong-purpose":
				claims["type"] = "access"
			case "missing-state":
				delete(claims, "state")
			}
			signed := prodAuthSigned(t, p, claims, nil, nil)
			state, err := p.parseOAuthState(signed)
			if (err == nil) != (change == "valid") {
				t.Fatalf("OAuth state validation error = %v for %s", err, change)
			}
			if err == nil && (state.State != "browser-state" || state.ReturnTo != "/account") {
				t.Fatalf("state round trip = %+v", state)
			}
		})
	}
}
