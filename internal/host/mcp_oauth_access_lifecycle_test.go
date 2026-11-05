package host

import (
	"crypto/sha256"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestMCPExchangeCleanupRetainsInflightAccess(t *testing.T) {
	for _, scenario := range []string{"refresh", "refresh-with-intermediate-charge", "expiry"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			c := discoverMCPClient(t, f)
			registration := f.request("POST", "https://tunn.test/oauth/register", `{"client_name":"Spec client","redirect_uris":["`+c.redirect+`"],"grant_types":["authorization_code","refresh_token"]}`, "application/json", "", nil)
			var client mcpOAuthClient
			if registration.Code != 201 || json.Unmarshal(registration.Body.Bytes(), &client) != nil {
				t.Fatalf("registration status %d", registration.Code)
			}
			c.clientID = client.ID
			c.query.Set("client_id", client.ID)
			exchange := func(form url.Values) exchangeTokens {
				t.Helper()
				w := f.request("POST", c.token, form.Encode(), "application/x-www-form-urlencoded", "", nil)
				var tokens exchangeTokens
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &tokens) != nil || tokens.Access == "" || tokens.Refresh == "" {
					t.Fatalf("exchange status %d", w.Code)
				}
				return tokens
			}
			tokens := exchange(c.tokenForm(c.code(t)))
			digest := sha256.Sum256([]byte(tokens.Access))
			grant, err := f.p.meter.Resolve(t.Context(), &mp.ResolveRequest{Owner: f.tunnel.AccountID, Endpoint: "tools", TokenSha256: digest[:]})
			if err != nil {
				t.Fatal(err)
			}
			// Both requests share the original access grant; finishing just one must
			// not let an unrelated issuance reclaim the other's authority row.
			ids := []string{"00000000000000000000000000000001", "00000000000000000000000000000002"}
			for _, id := range ids {
				d, err := f.p.meter.Admit(t.Context(), &mp.Event{RequestId: id, Owner: grant.Owner, Endpoint: grant.Endpoint, GrantId: grant.Id, Caller: "grant:" + grant.Id, AuthMethod: "grant", Allowed: true, Reason: "allowed"})
				if err != nil || !d.Allowed {
					t.Fatalf("admit=%v error=%v", d, err)
				}
				d, err = f.p.meter.Charge(t.Context(), &mp.ChargeRequest{RequestId: id, RequestBytes: 2, ResponseBytes: 3})
				if err != nil || !d.Allowed {
					t.Fatalf("initial charge=%v error=%v", d, err)
				}
			}
			assertDenied := func(reason string) {
				t.Helper()
				for _, id := range ids {
					d, err := f.p.meter.Charge(t.Context(), &mp.ChargeRequest{RequestId: id, RequestBytes: 4, ResponseBytes: 6})
					if err != nil || d.Allowed || d.Reason != reason || d.Status != 403 || d.RequestBytes != 2 || d.ResponseBytes != 3 {
						t.Fatalf("in-flight charge=%v error=%v; want %s/403 with unchanged bytes", d, err, reason)
					}
				}
			}
			reason := "grant_revoked"
			if scenario == "expiry" {
				grant.ExpiresAt = time.Now().Add(-time.Second).UnixMilli()
				data, err := json.Marshal(grant)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.p.mcpOAuth.db.Exec(`UPDATE meter_grants SET expires=?,data=? WHERE id=?`, grant.ExpiresAt, data, grant.Id); err != nil {
					t.Fatal(err)
				}
				// A separate consent's authorization-code exchange runs the same cleanup.
				tokens = exchange(c.tokenForm(c.code(t)))
				reason = "grant_expired"
			} else {
				tokens = exchange(refreshExchangeForm(c.clientID, tokens.Refresh))
				if scenario == "refresh-with-intermediate-charge" {
					assertDenied(reason)
				}
				tokens = exchange(refreshExchangeForm(c.clientID, tokens.Refresh))
			}
			assertDenied(reason)
			assertRetained := func(want int) {
				t.Helper()
				var count int
				if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM meter_grants WHERE id=?`, grant.Id).Scan(&count); err != nil || count != want {
					t.Fatalf("retained grant count=%d want=%d error=%v", count, want, err)
				}
			}
			for i, id := range ids {
				if _, err := f.p.meter.Finish(t.Context(), &mp.Event{RequestId: id, Status: 403, Forwarded: true, ResponseBytes: 3}); err != nil {
					t.Fatal(err)
				}
				tokens = exchange(refreshExchangeForm(c.clientID, tokens.Refresh))
				assertRetained(1 - i)
			}
			var mappings int
			if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM mcp_oauth_access WHERE grant_id=?`, grant.Id).Scan(&mappings); err != nil || mappings != 0 {
				t.Fatalf("reclaimed grant mappings=%d error=%v", mappings, err)
			}
			out, err := f.p.meter.Export(t.Context(), &mp.ExportRequest{Owner: grant.Owner, Endpoint: grant.Endpoint})
			if err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, e := range out.Events {
				if e.RequestId == ids[0] || e.RequestId == ids[1] {
					found++
					if !e.Finished || e.Reason != reason || e.Status != 403 || e.RequestBytes != 2 || e.ResponseBytes != 3 {
						t.Fatalf("finished audit=%v", e)
					}
				}
			}
			if found != 2 || out.OwnerUsage.RequestBytes != 4 || out.OwnerUsage.ResponseBytes != 6 {
				t.Fatalf("audits=%d usage=%v", found, out.OwnerUsage)
			}
		})
	}
}

// The published hosted callbacks are treated as identifiers, never contacted.
func TestMCPOAuthHostedCallbackReplay(t *testing.T) {
	for _, callback := range []string{"https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback", "https://chatgpt.com/connector_platform_oauth_redirect"} {
		t.Run(callback, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			c := discoverMCPClient(t, f)
			body, _ := json.Marshal(map[string]any{"client_name": "Spec client", "redirect_uris": []string{callback}, "grant_types": []string{"authorization_code", "refresh_token"}})
			w := f.request("POST", "https://tunn.test/oauth/register", string(body), "application/json", "", nil)
			var client mcpOAuthClient
			if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &client) != nil {
				t.Fatalf("register: %d %s", w.Code, w.Body)
			}
			c.clientID, c.redirect = client.ID, callback
			c.query.Set("client_id", client.ID)
			c.query.Set("redirect_uri", callback)
			exchange := func(form url.Values) exchangeTokens {
				t.Helper()
				w := f.request("POST", c.token, form.Encode(), "application/x-www-form-urlencoded", "", nil)
				var tokens exchangeTokens
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &tokens) != nil || tokens.Access == "" || tokens.Refresh == "" {
					t.Fatalf("exchange: %d %s", w.Code, w.Body)
				}
				return tokens
			}
			tokens := exchange(c.tokenForm(c.code(t)))
			digest := sha256.Sum256([]byte(tokens.Access))
			grant, err := f.p.meter.Resolve(t.Context(), &mp.ResolveRequest{Owner: f.tunnel.AccountID, Endpoint: "tools", TokenSha256: digest[:]})
			if err != nil {
				t.Fatal(err)
			}
			grant.ExpiresAt = time.Now().Add(-time.Second).UnixMilli()
			data, _ := json.Marshal(grant)
			if _, err := f.p.mcpOAuth.db.Exec(`UPDATE meter_grants SET expires=?,data=? WHERE id=?`, grant.ExpiresAt, data, grant.Id); err != nil {
				t.Fatal(err)
			}
			if w := f.request("POST", c.resource, `{}`, "application/json", tokens.Access, nil); w.Code != 401 {
				t.Fatalf("expired token: %d", w.Code)
			}
			tokens = exchange(refreshExchangeForm(c.clientID, tokens.Refresh))
			if _, err := f.p.mcpOAuth.db.Exec(`DELETE FROM mcp_oauth_clients WHERE id=?`, c.clientID); err != nil {
				t.Fatal(err)
			}
			w = f.request("POST", c.token, refreshExchangeForm(c.clientID, tokens.Refresh).Encode(), "application/x-www-form-urlencoded", "", nil)
			if w.Code != 401 || !strings.Contains(w.Body.String(), `"invalid_client"`) {
				t.Fatalf("deleted: %d %s", w.Code, w.Body)
			}
		})
	}
}
