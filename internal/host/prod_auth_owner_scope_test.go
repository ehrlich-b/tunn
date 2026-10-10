package host

import (
	"context"
	"net/url"
	"strings"
	"testing"

	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestProdAuthGrantOwnerMutationScope(t *testing.T) {
	for _, route := range prodAuthRoutes {
		if route.method != "DELETE" && route.method != "POST" || !strings.HasPrefix(route.path, "/api/") || route.pattern == "/api/device/code" || route.pattern == "/api/reports" {
			continue
		}
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			f := newProdAuthFixture(t)
			pendingCode, pendingConsent := f.client.code(t), f.client.consentForm(t)
			w := f.routeRequest(t, route, "other-jwt", "tunn.test")
			if w.Code != route.want[2] {
				t.Fatalf("other-owner decision = %d, want %d: %s", w.Code, route.want[2], w.Body)
			}
			grants, err := f.p.meter.ListGrants(context.Background(), &meterpb.ListGrantsRequest{Owner: f.tunnel.AccountID, Endpoint: "tools"})
			if err != nil || len(grants.Grants) != 2 {
				t.Fatalf("another account changed the owner's grants: %v, error %v", grants, err)
			}
			for _, grant := range grants.Grants {
				if grant.Revoked {
					t.Fatal("another account revoked the owner's grant")
				}
			}
			keyOwner, err := f.p.sshKeys.Owner(context.Background(), f.fingerprint)
			if err != nil || keyOwner != "owner@example.com" {
				t.Fatalf("another account changed SSH ownership: %q, error %v", keyOwner, err)
			}
			owner := f.credentials["owner-jwt"]
			for _, path := range []string{"/api/domains", "/api/hosts"} {
				listed := f.request("GET", "https://tunn.test"+path, "", "", owner, nil)
				expected := "work.example.com"
				if path == "/api/hosts" {
					expected = "workstation"
				}
				if listed.Code != 200 || !strings.Contains(listed.Body.String(), expected) {
					t.Fatalf("another account removed owner inventory: %d %s", listed.Code, listed.Body)
				}
			}
			if exchanged := f.request("POST", f.client.token, f.client.tokenForm(pendingCode).Encode(), "application/x-www-form-urlencoded", "", nil); exchanged.Code != 200 {
				t.Fatalf("another account invalidated pending code: %d %s", exchanged.Code, exchanged.Body)
			}
			consented := f.request("POST", f.client.authorize, pendingConsent.Encode(), "application/x-www-form-urlencoded", "", f.client.cookie)
			location, err := url.Parse(consented.Header().Get("Location"))
			if err != nil || consented.Code != 302 || location.Query().Get("code") == "" {
				t.Fatalf("another account invalidated pending consent: %d %s", consented.Code, consented.Header())
			}
		})
	}
}
