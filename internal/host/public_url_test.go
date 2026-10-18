package host

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/metering"
)

func TestRelayPublishedURLPorts(t *testing.T) {
	for _, port := range []string{"", ":443", ":18443"} {
		t.Run("port"+port, func(t *testing.T) {
			f := newDurablePublisherFixture(t)
			f.relay.config.PublicAddr = "tunn.test" + port
			f.publisher.PublicPath = "/mcp"
			f.publisher.EndpointProtocol = "http"
			f.publisher.Quiet = false
			f.relay.tunnelServer.SetSharingBackend(f.login.meter.(metering.SharingBackend))
			want := "https://durable-reconnect.tunn.test"
			if port == ":18443" {
				want += port
			}
			done := f.run(t)
			for {
				select {
				case err := <-done:
					t.Fatal(err)
				case event := <-f.events:
					if event.State != client.StateReady {
						continue
					}
					if event.PublicURL != want+"/mcp" {
						t.Fatalf("printed URL %q, want %q", event.PublicURL, want+"/mcp")
					}
					if f.relay.mcpResource("durable-reconnect") != event.PublicURL {
						t.Fatal("printed URL differs from OAuth resource")
					}
					t.Logf("PASS registration and CLI output preserve canonical URL %s", event.PublicURL)
					return
				case <-time.After(5 * time.Second):
					t.Fatal("registration timeout")
				}
			}
		})
	}
}

func TestRelayReturnDestinationPorts(t *testing.T) {
	f := newMCPOAuthFixture(t)
	f.p.config.PublicAddr = "tunn.test:18443"
	for _, target := range []string{"https://tools.tunn.test:18443/mcp", "https://tunn.test:18443/account"} {
		if got := f.p.sanitizeReturnTo(target); got != target {
			t.Fatalf("lost return destination %q: %q", target, got)
		}
	}
	for _, target := range []string{"https://tools.tunn.test/mcp", "https://tools.tunn.test:443/mcp", "https://tools.tunn.test:18444/mcp", "https://tunn.test.evil.test:18443/", "http://tools.tunn.test:18443/"} {
		if got := f.p.sanitizeReturnTo(target); got != "/" {
			t.Fatalf("accepted return destination %q", target)
		}
	}
}

func TestMCPConsentPolicyAndOrigin(t *testing.T) {
	f := newMCPOAuthFixture(t)
	c := discoverMCPClient(t, f)
	form := c.consentForm(t)
	page := f.request("GET", c.authorize+"?"+c.query.Encode(), "", "", "", c.cookie)
	policy := page.Header().Get("Content-Security-Policy")
	if page.Header().Get("Referrer-Policy") != "same-origin" || !strings.Contains(policy, "form-action 'self' "+c.redirect+";") || !strings.Contains(policy, "base-uri 'none'") {
		t.Fatalf("unsafe consent policy: %s", page.Header())
	}
	for _, origin := range []string{"null", "https://attacker.test", "https://tools.tunn.test", "https://tunn.test:18443", ""} {
		r := httptest.NewRequest("POST", c.authorize, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.AddCookie(c.cookie)
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" {
			t.Fatalf("origin %q accepted: %d", origin, w.Code)
		}
	}
	// A malformed redirect cannot introduce another CSP directive.
	c.query.Set("redirect_uri", "https://connector.example/cb;evil?x=;script-src%20*")
	registered, err := f.p.mcpOAuth.client(t.Context(), c.clientID)
	if err != nil {
		t.Fatal(err)
	}
	registered.ID += "_policy"
	registered.RedirectURIs = []string{c.query.Get("redirect_uri")}
	if err := f.p.mcpOAuth.register(t.Context(), registered); err != nil {
		t.Fatal(err)
	}
	c.query.Set("client_id", registered.ID)
	page = f.request("GET", c.authorize+"?"+c.query.Encode(), "", "", "", c.cookie)
	if page.Code != 200 || strings.Contains(page.Header().Get("Content-Security-Policy"), "/cb;evil") || strings.Contains(page.Header().Get("Content-Security-Policy"), "script-src") {
		t.Fatal("callback escaped CSP source")
	}
}
