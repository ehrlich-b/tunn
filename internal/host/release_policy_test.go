package host

import (
	"strings"
	"testing"
)

func TestViewerPolicy(t *testing.T) {
	p, _, _ := revenueFixture(t)
	for _, path := range []string{"/terms", "/privacy"} {
		w := revenueRequest(t, p, path, false)
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		count := strings.Count(w.Body.String(), "Shared viewers are free and unlimited; fair use applies (see terms).")
		if path == "/terms" && count != 1 || path == "/privacy" && count != 0 {
			t.Errorf("%s: approved sentence count %d", path, count)
		}
	}
}

func TestReleasePolicy(t *testing.T) {
	p, _, _ := revenueFixture(t)
	cases := map[string][]string{
		"/terms":   {"Google, GitHub, or an email link", "10 GB", "500 GB", "5 concurrent tunnels", "25 concurrent tunnels", "1 reserved", "10", "Requests are unlimited subject to fair use", "Stripe"},
		"/privacy": {"sign-in methods configured by its operator", "configured email provider", "Authentication providers process information when their methods are configured and used", "Stripe processes payments", "does not delete retained usage records", "deletion across active stores and backups are under review"},
	}
	for path, wants := range cases {
		w := revenueRequest(t, p, path, false)
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		body := w.Body.String()
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %q", path, want)
			}
		}
		for _, forbidden := range []string{"1000000 admissions", "10000000 admissions", "retained for 30 days", "deletion is completed"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s contains %q", path, forbidden)
			}
		}
	}
}
