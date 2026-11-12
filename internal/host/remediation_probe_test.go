package host

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Follow the complete signup journey: a successful link redirect alone does
// not establish a usable browser session.
func TestRemediationPublicHostSession(t *testing.T) {
	for _, public := range []string{"tunn.test", "login.test"} {
		t.Run(public, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			f.p.config.PublicAddr = public
			f.p.emailSender = new(accountsMailCapture)
			browser := funnelBrowser(t, f.p)
			funnelVisit(t, browser, "https://tunn.test/docs?src=alt")
			funnelVisit(t, browser, "https://"+public+"/auth/login")
			funnelSignup(t, browser, f.p, public)
			browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			response, err := browser.Get("https://" + public + "/account")
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("account after signup: status=%d location=%q; want 200 authenticated", response.StatusCode, response.Header.Get("Location"))
			}
			var n int
			if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='signup' AND source='alt'`).Scan(&n); err != nil || n != 1 {
				t.Fatalf("attributed signups=%d err=%v", n, err)
			}
		})
	}
}

func TestRemediationStatusFirstTouch(t *testing.T) {
	for _, public := range []string{"tunn.test", "login.test"} {
		t.Run(public, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			f.p.config.PublicAddr = public
			f.p.emailSender = new(accountsMailCapture)
			browser := funnelBrowser(t, f.p)
			funnelVisit(t, browser, "https://tunn.test/status")
			funnelVisit(t, browser, "https://tunn.test/docs?src=alt")
			funnelVisit(t, browser, "https://"+public+"/auth/login?src=saashub")
			funnelSignup(t, browser, f.p, public)
			var n int
			if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='signup' AND source='direct'`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 2 {
				t.Fatalf("direct status first touch replaced by alt: direct=%d want=2", n)
			}
		})
	}
}

func TestRemediationEntryInventory(t *testing.T) {
	for _, path := range []string{"/", "/about", "/privacy", "/terms", "/pricing", "/ngrok-alternative", "/docs", "/docs/status", "/agents", "/agents/SKILLS.md", "/status", "/report", "/login", "/auth/login", "/upgrade"} {
		t.Run(strings.ReplaceAll(path, "/", "_"), func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "https://tunn.test"+path, nil)
			if !funnelSourceEntry(req) {
				t.Errorf("browser entry %s is absent from first-touch policy", path)
			}
		})
	}
	for _, path := range []string{"/health", "/healthz", "/readyz", "/status.json", "/install.sh", "/dl/tunn", "/api/device/code", "/webhooks/stripe", "/favicon.ico", "/auth/verify?token=fixture", "/auth/google?org=disabled"} {
		req, _ := http.NewRequest(http.MethodGet, "https://tunn.test"+path, nil)
		if funnelSourceEntry(req) {
			t.Errorf("background or callback %s must not establish first touch", path)
		}
	}
}
