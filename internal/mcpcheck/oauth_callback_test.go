package mcpcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectorCallbackResultValidation(t *testing.T) {
	const code = "fixture-code&+ café"
	const token = "fixture-token"
	d := &Discovery{Issuer: "https://relay.test", Token: "https://relay.test/token"}
	valid := "state=fixture-state&iss=https%3A%2F%2Frelay.test&code=" + url.QueryEscape(code)
	for _, tt := range []struct {
		name, query string
		valid       bool
	}{
		{"encoded value", valid, true},
		{"encoded keys", "st%61te=fixture-state&%69ss=https%3A%2F%2Frelay.test&%63ode=" + url.QueryEscape(code), true},
		{"duplicate state same", valid + "&state=fixture-state", false},
		{"duplicate state different", valid + "&state=wrong", false},
		{"duplicate state empty first", "state=&" + valid, false},
		{"duplicate state encoded key", valid + "&st%61te=fixture-state", false},
		{"duplicate code same", valid + "&code=" + url.QueryEscape(code), false},
		{"duplicate code different", valid + "&code=other-code", false},
		{"duplicate code empty first", "code=&" + valid, false},
		{"duplicate code encoded key", valid + "&co%64e=other-code", false},
		{"duplicate error same", "state=fixture-state&iss=https://relay.test&error=access_denied&error=access_denied", false},
		{"duplicate error empty first", "state=fixture-state&iss=https://relay.test&error=&error=access_denied", false},
		{"duplicate error empty last", "state=fixture-state&iss=https://relay.test&error=access_denied&error=", false},
		{"duplicate error encoded key", "state=fixture-state&iss=https://relay.test&error=&%65rror=", false},
		{"code and error", valid + "&error=access_denied", false},
		{"error and code", "error=access_denied&" + valid, false},
		{"code and empty error", valid + "&error=", false},
		{"code and bare error", valid + "&error", false},
		{"empty code and error", "state=fixture-state&iss=https://relay.test&code=&error=access_denied", false},
		{"empty state", "state=&iss=https://relay.test&code=" + url.QueryEscape(code), false},
		{"empty code", "state=fixture-state&iss=https://relay.test&code=", false},
		{"bare code", "state=fixture-state&iss=https://relay.test&code", false},
		{"empty error", "state=fixture-state&iss=https://relay.test&error=", false},
		{"denied", "state=fixture-state&iss=https://relay.test&error=access_denied", false},
		{"missing result", "state=fixture-state&iss=https://relay.test", false},
		{"empty issuer", "state=fixture-state&iss=&code=" + url.QueryEscape(code), false},
		{"duplicate issuer", valid + "&iss=https://relay.test", false},
		{"malformed escape", valid + "&error=%ZZ", false},
		{"unescaped semicolon", valid + ";error=access_denied", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			posts := 0
			c := New(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				posts++
				if r.URL.String() != d.Token || r.Method != "POST" {
					t.Fatal("unexpected token request")
				}
				if err := r.ParseForm(); err != nil || r.PostForm.Get("code") != code {
					t.Fatal("encoded authorization code changed during exchange")
				}
				return response(200, `{"access_token":"fixture-token","token_type":"Bearer","scope":"mcp","expires_in":3600}`), nil
			}))
			a := &Authorization{discovery: d, redirect: "http://127.0.0.1:12345/callback", state: "fixture-state"}
			got, err := c.Exchange(t.Context(), a, a.redirect+"?"+tt.query)
			if tt.valid {
				if err != nil || got != token || posts != 1 {
					t.Fatal("valid encoded callback did not exchange exactly once")
				}
			} else {
				if err == nil || got != "" || posts != 0 {
					t.Fatal("invalid callback accepted or caused token exchange")
				}
				for _, secret := range []string{code, url.QueryEscape(code), token, "other-code", "access_denied"} {
					if strings.Contains(err.Error(), secret) {
						t.Fatal("failure output leaked callback credentials")
					}
				}
				if strings.Contains(tt.name, "duplicate error") {
					requireProblem(t, err, "callback")
				}
			}
		})
	}
}

func TestConnectorCallbackExchangeOneShot(t *testing.T) {
	for _, status := range []int{200, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var posts atomic.Int32
			c := New(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				posts.Add(1)
				return response(status, `{"access_token":"fixture-token","token_type":"Bearer","scope":"mcp","expires_in":3600}`), nil
			}))
			a := &Authorization{discovery: &Discovery{Issuer: "https://relay.test", Token: "https://relay.test/token"}, redirect: "http://127.0.0.1:12345/callback", state: "fixture-state"}
			callback := a.redirect + "?state=fixture-state&iss=https://relay.test&code=fixture-code"
			token, err := c.Exchange(t.Context(), a, callback)
			if status == 200 && (err != nil || token != "fixture-token") || status != 200 && (err == nil || token != "") || posts.Load() != 1 {
				t.Fatal("first callback did not make exactly one token request")
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					token, err := c.Exchange(t.Context(), a, callback)
					if token != "" || err == nil {
						t.Error("replayed callback accepted")
					} else if strings.Contains(err.Error(), "fixture-code") || strings.Contains(err.Error(), "fixture-token") {
						t.Error("replay failure leaked credentials")
					}
				})
			}
			wg.Wait()
			if posts.Load() != 1 {
				t.Fatal("replayed callback made another token request")
			}
		})
	}
}

func TestConnectorLiveCallbackReplayWhileExchanging(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	d := &Discovery{Issuer: "https://relay.test", Register: "https://relay.test/register", Authorize: "https://relay.test/authorize", Token: "https://relay.test/token"}
	started, release := make(chan struct{}), make(chan struct{})
	var posts atomic.Int32
	c := New(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == d.Register {
			var registration map[string]any
			if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
				return nil, err
			}
			registration["client_id"] = "fixture-client"
			body, _ := json.Marshal(registration)
			return response(201, string(body)), nil
		}
		if r.URL.String() != d.Token {
			t.Error("unexpected outbound request")
			return response(404, ""), nil
		}
		if posts.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return response(200, `{"access_token":"fixture-token","token_type":"Bearer","scope":"mcp","expires_in":3600}`), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}))
	links := make(chan string, 1)
	type result struct {
		token string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		token, err := c.Authenticate(ctx, d, func(link string) { links <- link })
		done <- result{token, err}
	}()
	var link string
	select {
	case link = <-links:
	case <-ctx.Done():
		t.Fatal("authorization did not start")
	}
	u, _ := url.Parse(link)
	q := u.Query()
	callback := q.Get("redirect_uri") + "?" + url.Values{"state": {q.Get("state")}, "iss": {d.Issuer}, "code": {"fixture-code"}}.Encode()
	check := func(want int) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, "GET", callback, nil)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal("local callback request failed")
		}
		body, readErr := io.ReadAll(res.Body)
		res.Body.Close()
		if readErr != nil || res.StatusCode != want {
			t.Fatalf("callback status %d, want %d", res.StatusCode, want)
		}
		if strings.Contains(string(body), "fixture-code") || strings.Contains(string(body), "fixture-token") {
			t.Fatal("callback response leaked credentials")
		}
	}
	check(200)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("token exchange did not start")
	}
	// The receiver has drained the callback channel, but exchange is still pending.
	check(409)
	close(release)
	select {
	case got := <-done:
		if got.err != nil || got.token != "fixture-token" || posts.Load() != 1 {
			t.Fatal("valid callback did not finish with exactly one exchange")
		}
	case <-ctx.Done():
		t.Fatal("token exchange did not finish")
	}
}

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
				body, readErr := io.ReadAll(res.Body)
				res.Body.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				for _, secret := range []string{"fixture-code", "fixture-token"} {
					if strings.Contains(string(body), secret) {
						t.Fatal("callback response leaked credentials")
					}
				}
				if posts != attempt {
					t.Fatal("invalid callback caused token exchange")
				}
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
			for _, suffix := range []string{
				"&state=" + query.Get("state"), "&%73tate=wrong", "&state=",
				"&code=fixture-code", "&%63ode=other-code", "&code=",
				"&error=", "&error", "&error=access_denied",
				"&error=&error=access_denied", "&error=access_denied&error=",
			} {
				check("ambiguous result", callback+"?"+valid.Encode()+suffix, "", 400)
			}
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
