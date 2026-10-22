package host

import (
	"context"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/metering"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestSharingManagementSelectionAndExpiry(t *testing.T) {
	p, tunnel, ledger, _ := webSharingFixture(t)
	if _, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: "another-long-application-name", Mode: "private"}); err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: authCookieName, Value: relayJWT(t, p, "owner@example.com")}
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://tunn.test"+path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		return w
	}
	w := get("/account/sharing")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `action="?tunnel=another-long-application-name"`) || strings.Count(w.Body.String(), "<option ") != 2 {
		t.Fatalf("default selection: %d %s", w.Code, w.Body)
	}
	csrf := hiddenMCPField(t, w.Body.String(), "csrf_token")
	for _, explicit := range []bool{false, true} {
		form := url.Values{"email": {"alice@example.com"}, "action": {"share"}, "csrf_token": {csrf}}
		expiry := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Minute)
		if explicit {
			form.Set("expires", expiry.Format("2006-01-02T15:04"))
		}
		r := httptest.NewRequest("POST", "https://tunn.test/account/sharing?tunnel=another-long-application-name", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://tunn.test")
		r.AddCookie(cookie)
		result := httptest.NewRecorder()
		p.createHandler().ServeHTTP(result, r)
		if result.Code != 303 {
			t.Fatalf("share: %d %s", result.Code, result.Body)
		}
		out, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "get", Owner: tunnel.AccountID, Endpoint: "another-long-application-name"})
		if err != nil {
			t.Fatal(err)
		}
		var active []*mp.Grant
		for _, person := range out.Resources[0].People {
			if !person.Revoked && person.ExpiresAt > time.Now().UnixMilli() {
				active = append(active, person)
			}
		}
		if len(active) != 1 {
			t.Fatalf("duplicate person: %v", active)
		}
		if explicit && active[0].ExpiresAt != expiry.UnixMilli() || !explicit && active[0].ExpiresAt < time.Now().AddDate(50, 0, 0).UnixMilli() {
			t.Fatalf("changed expiry: %v", active[0])
		}
		w = get("/account/sharing?tunnel=another-long-application-name")
		if strings.Count(w.Body.String(), `class="sharing-name">alice@example.com`) != 1 {
			t.Fatal("person rendered more than once")
		}
		if strings.Contains(w.Body.String(), "Expires "+expiry.Format("Jan 2, 2006")) != explicit {
			t.Fatal("explicit expiry missing or default expiry repeated")
		}
	}
	// A bare POST must not pick a tunnel on the owner's behalf.
	r := httptest.NewRequest("POST", "https://tunn.test/account/sharing", strings.NewReader("action=share&email=wrong@example.com"))
	r.AddCookie(cookie)
	result := httptest.NewRecorder()
	p.createHandler().ServeHTTP(result, r)
	if result.Code != 400 {
		t.Fatal("mutation inferred a target", result.Code)
	}
}

func TestSharingManagementHumanOutcomes(t *testing.T) {
	for reason, want := range map[string]string{
		"authentication_required": "Sign-in required", "allowlist_denied": "Access denied",
		"grant_expired": "Access expired", "grant_revoked": "Access removed or expired",
		"permission_authority_unavailable": "Temporarily unavailable", "endpoint_offline": "Tunnel offline",
		"owner_request_budget": "Usage limit reached", "future_internal_reason": "Access denied",
	} {
		if got := sharingOutcome(&mp.Event{Reason: reason}); got != want {
			t.Errorf("%s: %s", reason, got)
		}
	}
	if sharingOutcome(&mp.Event{Allowed: true, Reason: "allowed"}) != "Access allowed" {
		t.Fatal("allowed outcome changed")
	}
	groups := []struct{ Subject, Name string }{{"group:company:engineering", "Company · Engineering"}}
	if sharingPersonName("group:company:engineering", groups) != "Company · Engineering" || sharingPersonName("group:old:group", nil) != "Company group" || sharingPersonName("email:alice@example.com", nil) != "alice@example.com" {
		t.Fatal("identity labels expose internal subjects")
	}
}

func TestSharingManagementCopy(t *testing.T) {
	p, _, _, _ := webSharingFixture(t)
	r := httptest.NewRequest("GET", "https://tunn.test/account/sharing?tunnel=api", nil)
	r.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, p, "owner@example.com")})
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	text := w.Body.String()
	text = text[strings.Index(text, "<main"):strings.Index(text, "</main>")]
	for _, forbidden := range []string{"No scheduled expiry", "polling", "refreshed", "15 minutes", "web resource", "denied:", "authentication_required"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("management copy contains %q", forbidden)
		}
	}
	for _, needed := range []string{"Only you and people with access", "always have access", "within five seconds", "Set expiry", "Recent access"} {
		if !strings.Contains(text, needed) {
			t.Errorf("missing permission copy %q", needed)
		}
	}
}

func TestSharingManagementCapacityUnchanged(t *testing.T) {
	p, tunnel, ledger, _ := webSharingFixture(t)
	people := make([]string, metering.MaxResourcePeople)
	for i := range people {
		people[i] = fmt.Sprintf("person-%02d@example.com", i)
	}
	if _, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: "at-capacity", Mode: "private", InitialEmails: people}); err != nil {
		t.Fatal(err)
	}
	w := sharingCall(t, p, "POST", "at-capacity", relayJWT(t, p, "owner@example.com"), `{"email":"one-more@example.com"}`)
	if w.Code != 429 {
		t.Fatalf("capacity changed: %d %s", w.Code, w.Body)
	}
}
