package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/golang-jwt/jwt/v4"
)

func reviewRawEmail(t *testing.T, p *ProxyServer, token, want string) {
	t.Helper()
	parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return p.getJWTSigningKey(), nil })
	if err != nil || !parsed.Valid {
		t.Fatal("invalid issued token", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["email"] != want || (claims["sub"] != nil && claims["sub"] != want) {
		t.Errorf("noncanonical issued claims: %v", claims)
	}
}

// Existing rows and pre-fix sessions must remain revocable, including an alias
// in the owner's bucket. Full-width addresses pin the account's NFKC policy,
// preventing a lowercase-only substitute for common.NormalizeEmail.
func TestReviewExistingDeviceOwnerCompatibility(t *testing.T) {
	for _, owner := range []string{"Owner@Example.COM", " Alias@Example.COM ", "Ｏｗｎｅｒ@Example.COM"} {
		t.Run(owner, func(t *testing.T) {
			p := durableFixture(t)
			_, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"owner@example.com", "alias@example.com"}, "github")
			if err != nil {
				t.Fatal(err)
			}
			token := durableLogin(t, p)
			if _, err := p.devices.db.Exec(`UPDATE durable_devices SET email=? WHERE id=?`, owner, token.Device); err != nil {
				t.Fatal(err)
			}
			// Reopen the registry without a backfill, just as a relay upgrade does.
			p.devices, err = newDeviceCredentialStore(p.devices.db)
			if err != nil {
				t.Fatal(err)
			}
			w, rotated := durableRefresh(p, token.Refresh, strings.Repeat("a", 43))
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			reviewRawEmail(t, p, rotated.Access, common.NormalizeEmail(owner))
			w, retried := durableRefresh(p, token.Refresh, strings.Repeat("a", 43))
			if w.Code != 200 || retried.Refresh != rotated.Refresh {
				t.Fatal("existing owner's retry failed", w.Code)
			}
			reviewRawEmail(t, p, retried.Access, common.NormalizeEmail(owner))

			// Mint the old raw session directly; using setAuthCookie would mask
			// compatibility bugs once that setter canonicalizes new sessions.
			raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"email": owner, "type": "session", "exp": time.Now().Add(time.Hour).Unix()}).SignedString(p.getJWTSigningKey())
			if err != nil {
				t.Fatal(err)
			}
			cookie := &http.Cookie{Name: authCookieName, Value: raw}
			get := httptest.NewRequest("GET", "https://tunn.test/account/devices", nil)
			get.AddCookie(cookie)
			w = httptest.NewRecorder()
			p.handleDevices(w, get)
			if w.Code != 200 || !strings.Contains(w.Body.String(), token.Device) {
				t.Error("existing owner cannot list device", w.Code)
			}
			csrf, err := p.createCSRFToken(get, "/account/devices")
			if err != nil {
				t.Fatal(err)
			}
			post := httptest.NewRequest("POST", "https://tunn.test/account/devices", strings.NewReader(url.Values{"device_id": {token.Device}, "csrf_token": {csrf}}.Encode()))
			post.AddCookie(cookie)
			post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			post.Header.Set("Origin", "https://tunn.test")
			w = httptest.NewRecorder()
			p.handleDevices(w, post)
			if w.Code != 303 {
				t.Error("existing owner cannot revoke device", w.Code)
			}
			w, _ = durableRefresh(p, rotated.Refresh, strings.Repeat("b", 43))
			if w.Code != 401 {
				t.Error("revoked existing device remains renewable", w.Code)
			}
		})
	}
}

func TestReviewPreviouslyAuthorizedCodeCanonicalizesAtExchange(t *testing.T) {
	for _, durable := range []bool{false, true} {
		p := durableFixture(t)
		code, err := p.storage.CreateDeviceCode(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.devices.db.Exec(`UPDATE device_codes SET authorized=1,email=? WHERE code=?`, " Owner@Example.COM ", code.Code); err != nil {
			t.Fatal(err)
		}
		path := "https://tunn.test/api/device/token?code=" + url.QueryEscape(code.Code)
		if durable {
			path += "&durable=1"
		}
		w := httptest.NewRecorder()
		p.handleDeviceToken(w, httptest.NewRequest("GET", path, nil))
		var token durableTokenFixture
		if !durable {
			if w.Code != 400 {
				t.Fatal("unscoped code granted management")
			}
			continue
		}
		if err := json.Unmarshal(w.Body.Bytes(), &token); err != nil || w.Code != 200 {
			t.Fatal("old authorized code exchange failed", w.Code, err)
		}
		reviewRawEmail(t, p, token.Access, "owner@example.com")
		if durable {
			var owner string
			if err := p.devices.db.QueryRow(`SELECT email FROM durable_devices WHERE id=?`, token.Device).Scan(&owner); err != nil || owner != "owner@example.com" {
				t.Fatal("old code created noncanonical device", owner, err)
			}
		}
	}
}
