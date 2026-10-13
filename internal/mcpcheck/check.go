// Package mcpcheck implements the client side of tunn's private MCP journey.
package mcpcheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const maxResponse = 1024 * 1024

// Problem deliberately excludes server bodies, URLs with query strings, tokens
// and transport error strings: each may contain credentials or private data.
type Problem struct{ Stage, Code, Action string }

func (p *Problem) Error() string               { return fmt.Sprintf("%s [%s]: %s", p.Stage, p.Code, p.Action) }
func problem(stage, code, action string) error { return &Problem{stage, code, action} }

// New preserves certificate verification, disables redirects and bounds every
// request. A caller may supply a transport for disposable local fixtures.
func New(transport http.RoundTripper) *Checker {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Checker{http: &http.Client{Transport: transport, Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type Checker struct{ http *http.Client }
type Discovery struct {
	Resource, Issuer, Authorize, Token, Register string
}

func httpsURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	return u, err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.RawQuery == "" && !u.ForceQuery && u.Opaque == ""
}
func sameOrigin(a, b *url.URL) bool { return a.Scheme == b.Scheme && a.Host == b.Host }
func transportProblem(stage string, err error) error {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var netErr net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return problem(stage, "cancelled", "Check cancelled; rerun when ready.")
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout():
		return problem(stage, "timeout", "Keep publisher and local server running; check network access and retry. Browser consent must finish before --timeout.")
	case errors.As(err, &dns):
		return problem(stage, "dns", "Check the printed Connector URL and DNS resolution from this machine.")
	case errors.As(err, &cert) || errors.As(err, &authority) || errors.As(err, &hostname):
		return problem(stage, "tls", "Use the printed HTTPS host with a valid trusted certificate; check relay certificates and your system clock.")
	default:
		return problem(stage, "network", "Check the Connector URL, publisher, relay and proxy/firewall connectivity; retry.")
	}
}
func statusProblem(stage string, status int) error {
	code, action := "http", "Check the printed /mcp URL and supported MCP upstream; retry after correcting the server."
	switch status {
	case 301, 302, 303, 307, 308:
		code, action = "redirect", "Use the exact HTTPS Connector URL; metadata and MCP endpoints must respond without redirects."
	case 400:
		code, action = "bad_request", "Check MCP protocol, exact OAuth resource, redirect URI and S256 PKCE parameters."
	case 401:
		code, action = "unauthorized", "Complete OAuth again; tokens expire or can be revoked. Sign in as the owner or an allowed email."
	case 403:
		code, action = "forbidden", "Check owner/allowed email and account state; approve the named tunnel in browser consent."
	case 404:
		code, action = "not_found", "Check /mcp and the running publisher. For a lost MCP session, rerun the check to initialize again."
	case 405:
		code, action = "method", "The upstream must support Streamable HTTP POST at its configured MCP path; standalone GET/SSE is optional."
	case 429:
		code, action = "rate_limit", "Respect Retry-After. For owner_request_budget or owner_byte_budget, inspect tunn usage; registration limits require waiting before retry."
	case 502:
		code, action = "upstream", "Start the local MCP server; check its executable, port, path and stderr."
	case 503:
		code, action = "unavailable", "Keep the publisher connected and retry. Self-hosters: check login-node OAuth, durable SQLite, JWT signing and grant authority configuration."
	case 504:
		code, action = "upstream_timeout", "Keep tools below the 25-second stdio bridge timeout (27-second forwarding timeout); return a job ID for longer work."
	}
	return problem(stage, code, fmt.Sprintf("HTTP %d. %s", status, action))
}
func (c *Checker) request(ctx context.Context, stage, method, target, contentType, token string, body []byte, headers http.Header) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, problem(stage, "url", "Use the printed HTTPS /mcp URL without credentials, query or fragment.")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, transportProblem(stage, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, nil, transportProblem(stage, err)
	}
	if len(data) > maxResponse {
		return nil, nil, problem(stage, "response_limit", "Response exceeds the diagnostic limit; reduce tool metadata or response size.")
	}
	return resp, data, nil
}
func decodeJSON(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("extra JSON")
	}
	return nil
}
func jsonResponse(stage string, resp *http.Response, data []byte, out any) error {
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" || decodeJSON(data, out) != nil {
		return problem(stage, "json", "Expected one JSON response; check the relay version and upstream protocol, not an HTML login page.")
	}
	return nil
}

var metadataPattern = regexp.MustCompile(`(?:^|[,\s])resource_metadata="([^"]+)"`)

func (c *Checker) Discover(ctx context.Context, raw string) (*Discovery, error) {
	resource, ok := httpsURL(raw)
	if !ok || resource.Path != "/mcp" || resource.RawPath != "" {
		return nil, problem("url", "url", "Copy the exact printed HTTPS Connector URL ending in /mcp, without credentials, query or fragment.")
	}
	if ip := net.ParseIP(resource.Hostname()); strings.EqualFold(resource.Hostname(), "localhost") || ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()) {
		return nil, problem("url", "local_url", "Use the public Connector URL, not localhost or a private address; hosted clients connect from their cloud.")
	}
	resp, _, err := c.request(ctx, "challenge", "POST", raw, "application/json", "", []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"tunn-check","version":"1"}}}`), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 401 {
		if resp.StatusCode == 200 || resp.StatusCode == 202 {
			return nil, problem("challenge", "public", "Endpoint accepts anonymous MCP requests; publish privately to verify the OAuth journey.")
		}
		return nil, statusProblem("challenge", resp.StatusCode)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	match := metadataPattern.FindStringSubmatch(challenge)
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") || len(match) != 2 {
		return nil, problem("challenge", "metadata_challenge", "Private /mcp must advertise Bearer resource_metadata; check relay OAuth support and the URL path.")
	}
	metadata, ok := httpsURL(match[1])
	if !ok || !sameOrigin(resource, metadata) {
		return nil, problem("resource_metadata", "origin", "Protected-resource metadata must be HTTPS on the connector origin; correct relay configuration.")
	}
	resp, data, err := c.request(ctx, "resource_metadata", "GET", metadata.String(), "", "", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, statusProblem("resource_metadata", resp.StatusCode)
	}
	var rm struct {
		Resource string   `json:"resource"`
		Servers  []string `json:"authorization_servers"`
		Scopes   []string `json:"scopes_supported"`
		Methods  []string `json:"bearer_methods_supported"`
	}
	if err := jsonResponse("resource_metadata", resp, data, &rm); err != nil {
		return nil, err
	}
	if rm.Resource != raw || len(rm.Servers) != 1 || !slices.Contains(rm.Scopes, "mcp") || !slices.Contains(rm.Methods, "header") {
		return nil, problem("resource_metadata", "resource", "Metadata must identify the exact /mcp resource, one issuer, mcp scope and header bearer support; check relay configuration.")
	}
	issuer, ok := httpsURL(rm.Servers[0])
	if !ok || issuer.Path != "" || issuer.RawPath != "" {
		return nil, problem("oauth_metadata", "issuer", "tunn's issuer must be an HTTPS platform origin; correct relay public address configuration.")
	}
	resp, data, err = c.request(ctx, "oauth_metadata", "GET", issuer.String()+"/.well-known/oauth-authorization-server", "", "", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, statusProblem("oauth_metadata", resp.StatusCode)
	}
	var as struct {
		Issuer    string   `json:"issuer"`
		Authorize string   `json:"authorization_endpoint"`
		Token     string   `json:"token_endpoint"`
		Register  string   `json:"registration_endpoint"`
		PKCE      []string `json:"code_challenge_methods_supported"`
		Methods   []string `json:"token_endpoint_auth_methods_supported"`
		Grants    []string `json:"grant_types_supported"`
		Responses []string `json:"response_types_supported"`
		Scopes    []string `json:"scopes_supported"`
	}
	if err := jsonResponse("oauth_metadata", resp, data, &as); err != nil {
		return nil, err
	}
	if as.Issuer != issuer.String() {
		return nil, problem("oauth_metadata", "issuer", "OAuth metadata issuer must match the protected-resource issuer exactly.")
	}
	if !slices.Contains(as.PKCE, "S256") || !slices.Contains(as.Methods, "none") || !slices.Contains(as.Grants, "authorization_code") || !slices.Contains(as.Responses, "code") || !slices.Contains(as.Scopes, "mcp") {
		return nil, problem("oauth_metadata", "pkce", "Relay must advertise S256 PKCE, public clients (none), authorization_code, code and mcp scope; update OAuth configuration.")
	}
	for _, endpoint := range []string{as.Authorize, as.Token, as.Register} {
		u, ok := httpsURL(endpoint)
		if !ok || !sameOrigin(issuer, u) || u.Path == "" {
			return nil, problem("oauth_metadata", "endpoint", "OAuth authorization, token and registration endpoints must be HTTPS on the issuer origin.")
		}
	}
	return &Discovery{raw, issuer.String(), as.Authorize, as.Token, as.Register}, nil
}
