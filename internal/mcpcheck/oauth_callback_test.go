package mcpcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestConnectorLiveCallbackRejectsWrongOriginStateAndStale(t *testing.T) {
	d := &Discovery{Issuer: "https://relay.test", Register: "https://relay.test/register", Authorize: "https://relay.test/authorize", Token: "https://relay.test/token", Resource: "https://tools.relay.test/mcp"}
	posts := 0
	c := New(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == d.Register {
			var registered map[string]any
			if err := json.NewDecoder(r.Body).Decode(&registered); err != nil {
				t.Fatal(err)
			}
			registered["client_id"] = "fixture-client"
			body, _ := json.Marshal(registered)
			return response(201, string(body)), nil
		}
		if r.URL.String() != d.Token {
			t.Fatal("unexpected outbound request")
		}
		posts++
		return response(200, `{"access_token":"fixture-token","token_type":"Bearer","scope":"mcp","expires_in":3600}`), nil
	}))
	var stale url.Values
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		token, err := c.Authenticate(ctx, d, func(link string) {
			authorize, _ := url.Parse(link)
			query := authorize.Query()
			callback := query.Get("redirect_uri")
			valid := url.Values{"code": {"fixture-code"}, "state": {query.Get("state")}, "iss": {d.Issuer}}
			check := func(name, raw, host string, want int) {
				req, _ := http.NewRequest("GET", raw, nil)
				if host != "" {
					req.Host = host
				}
				res, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode != want {
					t.Fatalf("%s: status %d, want %d", name, res.StatusCode, want)
				}
				t.Logf("PASS %s rejected without consuming pending callback", name)
			}
			check("wrong callback origin", callback+"?"+valid.Encode(), "attacker.test", 404)
			bad := url.Values{"code": {"fixture-code"}, "state": {"wrong"}, "iss": {d.Issuer}}
			check("wrong state", callback+"?"+bad.Encode(), "", 400)
			bad.Set("state", query.Get("state"))
			bad.Set("iss", "https://other.test")
			check("wrong issuer", callback+"?"+bad.Encode(), "", 400)
			if stale != nil {
				check("stale prior callback", callback+"?"+stale.Encode(), "", 400)
			}
			if posts != attempt {
				t.Fatal("invalid callback caused token exchange")
			}
			res, err := http.Get(callback + "?" + valid.Encode())
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != 200 {
				t.Fatal(fmt.Sprint("valid callback: ", res.StatusCode))
			}
			stale = valid
		})
		cancel()
		if err != nil || !strings.HasPrefix(token, "fixture-") || posts != attempt+1 {
			t.Fatalf("valid pending callback failed: %v, token posts %d", err, posts)
		}
	}
}
