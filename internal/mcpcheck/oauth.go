package mcpcheck

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Authorization holds secrets only in memory. Do not serialize or log it.
type Authorization struct {
	URL                                 string
	discovery                           *Discovery
	clientID, redirect, verifier, state string
}

func randomValue() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", problem("oauth", "random", "Secure randomness unavailable; retry after checking this machine.")
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func (c *Checker) BeginOAuth(ctx context.Context, d *Discovery, redirect string) (*Authorization, error) {
	u, err := url.Parse(redirect)
	if err != nil || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Scheme != "http" || u.Port() == "" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() {
		return nil, problem("oauth", "callback", "Use a local loopback HTTP callback with an explicit port.")
	}
	a := &Authorization{discovery: d, redirect: redirect}
	for _, dest := range []*string{&a.verifier, &a.state} {
		value, err := randomValue()
		if err != nil {
			return nil, err
		}
		*dest = value
	}
	body, _ := json.Marshal(map[string]any{"client_name": "tunn connector-check", "redirect_uris": []string{redirect}, "grant_types": []string{"authorization_code"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"})
	resp, data, err := c.request(ctx, "registration", "POST", d.Register, "application/json", "", body, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 201 {
		return nil, statusProblem("registration", resp.StatusCode)
	}
	var registered struct {
		ID        string   `json:"client_id"`
		Method    string   `json:"token_endpoint_auth_method"`
		Redirects []string `json:"redirect_uris"`
	}
	if err := jsonResponse("registration", resp, data, &registered); err != nil {
		return nil, err
	}
	if registered.ID == "" || len(registered.ID) > 2048 || registered.Method != "none" || len(registered.Redirects) != 1 || registered.Redirects[0] != redirect {
		return nil, problem("registration", "client", "Registration must return a public client and the exact callback; check relay version.")
	}
	a.clientID = registered.ID
	challenge := sha256.Sum256([]byte(a.verifier))
	query := url.Values{"response_type": {"code"}, "client_id": {a.clientID}, "redirect_uri": {redirect}, "resource": {d.Resource}, "scope": {"mcp"}, "state": {a.state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
	a.URL = d.Authorize + "?" + query.Encode()
	return a, nil
}

// CallbackCode checks response origin, state and issuer before any token POST.
func (a *Authorization) CallbackCode(raw string) (string, error) {
	u, err := url.Parse(raw)
	expected, _ := url.Parse(a.redirect)
	if err != nil || u.User != nil || u.Fragment != "" || !sameOrigin(u, expected) || u.Path != expected.Path {
		return "", problem("consent", "callback", "OAuth callback does not match the registered loopback address; restart the check.")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["state"]) != 1 || q.Get("state") != a.state || len(q["iss"]) != 1 || q.Get("iss") != a.discovery.Issuer {
		return "", problem("consent", "state", "OAuth state or issuer mismatch; restart the check and approve only its browser request.")
	}
	if q.Get("error") != "" {
		return "", problem("consent", "denied", "Consent was denied or invalid; sign in as owner/allowed email, choose automatic registration and approve this tunnel.")
	}
	if len(q["code"]) != 1 || q.Get("code") == "" || len(q.Get("code")) > 4096 {
		return "", problem("consent", "code", "Authorization code is missing or invalid; restart browser consent.")
	}
	return q.Get("code"), nil
}
func (c *Checker) Exchange(ctx context.Context, a *Authorization, callback string) (string, error) {
	code, err := a.CallbackCode(callback)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {a.clientID}, "code": {code}, "redirect_uri": {a.redirect}, "resource": {a.discovery.Resource}, "code_verifier": {a.verifier}}
	resp, data, err := c.request(ctx, "token", "POST", a.discovery.Token, "application/x-www-form-urlencoded", "", []byte(form.Encode()), nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", statusProblem("token", resp.StatusCode)
	}
	var result struct {
		Access  string `json:"access_token"`
		Type    string `json:"token_type"`
		Scope   string `json:"scope"`
		Expires int    `json:"expires_in"`
	}
	if err := jsonResponse("token", resp, data, &result); err != nil {
		return "", err
	}
	if result.Access == "" || len(result.Access) > 8192 || strings.ContainsAny(result.Access, "\r\n\t ") || !strings.EqualFold(result.Type, "Bearer") || result.Scope != "mcp" || result.Expires <= 0 {
		return "", problem("token", "token", "Expected an expiring Bearer token scoped to mcp; check authorization server configuration.")
	}
	return result.Access, nil
}

// Authenticate listens only on IPv4 loopback, prints the browser authorization
// URL via visit, and shuts down the listener on success, cancellation or timeout.
// It neither launches a browser nor persists credentials.
func (c *Checker) Authenticate(ctx context.Context, d *Discovery, visit func(string)) (string, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", problem("consent", "listener", "Allow a local loopback listener, then rerun --oauth on your desktop.")
	}
	defer listener.Close()
	redirect := "http://" + listener.Addr().String() + "/callback"
	a, err := c.BeginOAuth(ctx, d, redirect)
	if err != nil {
		return "", err
	}
	received := make(chan string, 1)
	server := &http.Server{ReadHeaderTimeout: 5e9, MaxHeaderBytes: 16 * 1024, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "GET" || r.Host != listener.Addr().String() || r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		callback := redirect + "?" + r.URL.RawQuery
		if _, err := a.CallbackCode(callback); err != nil {
			if p, ok := err.(*Problem); !ok || p.Code != "denied" {
				http.Error(w, "Invalid OAuth callback; retry the browser request.", 400)
				return
			}
		}
		select {
		case received <- callback:
			w.Write([]byte("Return to tunn connector-check for the result.\n"))
		default:
			http.Error(w, "Callback already received.", 409)
		}
	})}
	defer server.Close()
	go server.Serve(listener)
	visit(a.URL)
	select {
	case callback := <-received:
		return c.Exchange(ctx, a, callback)
	case <-ctx.Done():
		return "", transportProblem("consent", ctx.Err())
	}
}
