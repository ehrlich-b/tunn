package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const mcpMetadataLimit = 64 * 1024

// MCPCheckOptions authorizes only discovery at an explicit endpoint. A separate
// issuer is fetched only when the caller explicitly names its exact origin.
type MCPCheckOptions struct {
	Endpoint       string
	ExpectedIssuer string
	RootCAs        *x509.CertPool
}

type MCPDiscoveryCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

type MCPCheckReport struct {
	Ready       bool                `json:"ready"`
	Endpoint    string              `json:"endpoint,omitempty"`
	MetadataURL string              `json:"metadata_url,omitempty"`
	Issuer      string              `json:"issuer,omitempty"`
	Checks      []MCPDiscoveryCheck `json:"checks"`
	NextSteps   []string            `json:"next_steps"`
}

// CheckMCPDiscovery performs at most three unauthenticated GET requests. It does
// not initialize MCP, invoke tools, register a client, exchange a token, load
// saved credentials, or use cookies. Ready means this bounded discovery check
// passed; it does not claim either hosted application has accepted a connection.
func CheckMCPDiscovery(ctx context.Context, options MCPCheckOptions) (*MCPCheckReport, error) {
	report := &MCPCheckReport{Checks: []MCPDiscoveryCheck{}, NextSteps: []string{
		"Choose OAuth with a pre-registered public client ID. A tunn grant token is an access token, not an OAuth client ID or client secret; it cannot replace ChatGPT OAuth onboarding.",
		"Copy the exact ChatGPT redirect URI from its MCP connection management page into the server's configured client allowlist.",
		"In Claude choose your own OAuth client, enter the configured client ID, and leave the secret blank. Register https://claude.ai/api/mcp/auth_callback exactly.",
		"This checks discovery only. Confirm application sign-in, tool selection, cited answers, and independent grant revocation separately.",
	}}
	fail := func(name, message string) (*MCPCheckReport, error) {
		report.Checks = append(report.Checks, MCPDiscoveryCheck{Name: name, Message: message})
		return report, fmt.Errorf("%s: %s", name, message)
	}
	pass := func(name, message string) {
		report.Checks = append(report.Checks, MCPDiscoveryCheck{Name: name, Passed: true, Message: message})
	}
	endpoint, err := mcpHTTPSURL(options.Endpoint, false)
	if err != nil || endpoint.Path != "/mcp" || endpoint.RawPath != "" {
		return fail("endpoint", "Provide the literal HTTPS /mcp URL without user info, query, fragment, or an encoded path.")
	}
	report.Endpoint = options.Endpoint
	pass("endpoint", "Explicit HTTPS /mcp endpoint is safe for unauthenticated discovery.")
	expectedIssuer := ""
	if options.ExpectedIssuer != "" {
		if _, err := mcpHTTPSURL(options.ExpectedIssuer, true); err != nil {
			return fail("expected_issuer", "The expected issuer must be an HTTPS origin without a path, user info, query, or fragment.")
		}
		expectedIssuer = options.ExpectedIssuer
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxResponseHeaderBytes = mcpMetadataLimit
	transport.TLSClientConfig = &tls.Config{RootCAs: options.RootCAs, MinVersion: tls.VersionTLS12}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := mcpDiscoveryGET(ctx, httpClient, options.Endpoint)
	if err != nil {
		return fail("challenge", "Cannot reach the HTTPS endpoint with certificate verification: "+err.Error())
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		return fail("challenge", fmt.Sprintf("Expected unauthenticated HTTP 401, got %d. Enable OAuth discovery on this private /mcp route; redirects and login pages do not establish MCP authentication.", response.StatusCode))
	}
	challenge, err := mcpChallengeParameters(response.Header.Values("WWW-Authenticate"))
	if err != nil {
		return fail("challenge", "Return a Bearer challenge with one resource_metadata URL on HTTP 401. Grant-only bearer authentication does not provide application OAuth discovery.")
	}
	if scope, present := challenge["scope"]; present && scope != "mcp:access" {
		return fail("challenge_scope", "The Bearer scope challenge must request only mcp:access for this bounded route flow.")
	}
	metadataURL := challenge["resource_metadata"]
	metadata, err := mcpHTTPSURL(metadataURL, false)
	if err != nil || !mcpSameOrigin(endpoint, metadata) || metadata.RawPath != "" || (metadata.Path != "/.well-known/oauth-protected-resource" && metadata.Path != "/.well-known/oauth-protected-resource/mcp") {
		return fail("metadata_location", "The challenge must point to an HTTPS protected-resource well-known URL on the explicit endpoint's origin; no other location was fetched.")
	}
	report.MetadataURL = metadataURL
	pass("challenge", "HTTP 401 advertises protected-resource metadata on the endpoint origin.")
	var resource struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	if err := mcpReadMetadata(ctx, httpClient, metadataURL, &resource); err != nil {
		return fail("protected_resource_metadata", err.Error())
	}
	if resource.Resource != options.Endpoint {
		return fail("resource", "Metadata resource must exactly equal the entered MCP URL, including /mcp and its exact spelling.")
	}
	pass("resource", "Metadata resource exactly matches the entered /mcp URL.")
	if len(resource.AuthorizationServers) != 1 {
		return fail("issuer", "Configure exactly one authorization server issuer for this pre-registered-client flow.")
	}
	issuerText := resource.AuthorizationServers[0]
	issuer, err := mcpHTTPSURL(issuerText, true)
	if err != nil {
		return fail("issuer", "Metadata issuer must be an HTTPS origin without a path, user info, query, or fragment; no authorization server was fetched.")
	}
	report.Issuer = issuerText
	if expectedIssuer != "" && issuerText != expectedIssuer {
		return fail("issuer", "Metadata issuer does not exactly match --issuer; no authorization server was fetched.")
	}
	if expectedIssuer == "" && !mcpSameOrigin(endpoint, issuer) {
		report.NextSteps = append(report.NextSteps, "Review the discovered issuer, then rerun with --issuer "+issuerText+" to authorize that exact separate origin.")
		return fail("issuer", "A separate authorization server origin requires explicit --issuer approval before discovery.")
	}
	if !mcpHasValue(resource.ScopesSupported, "mcp:access") {
		return fail("scope", "Protected-resource metadata must advertise mcp:access for the bounded /mcp grant flow.")
	}
	pass("issuer", "A single exact HTTPS issuer is authorized for discovery.")
	var authorization struct {
		Issuer                   string   `json:"issuer"`
		AuthorizationEndpoint    string   `json:"authorization_endpoint"`
		TokenEndpoint            string   `json:"token_endpoint"`
		TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
		CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
		ResponseTypesSupported   []string `json:"response_types_supported"`
		GrantTypesSupported      []string `json:"grant_types_supported"`
		ScopesSupported          []string `json:"scopes_supported"`
		IssuerResponseSupported  bool     `json:"authorization_response_iss_parameter_supported"`
	}
	if err := mcpReadMetadata(ctx, httpClient, issuerText+"/.well-known/oauth-authorization-server", &authorization); err != nil {
		return fail("authorization_server_metadata", err.Error())
	}
	if authorization.Issuer != issuerText {
		return fail("issuer_match", "Authorization metadata issuer must exactly match protected-resource metadata, including any trailing slash.")
	}
	for _, location := range []string{authorization.AuthorizationEndpoint, authorization.TokenEndpoint} {
		parsed, err := mcpHTTPSURL(location, false)
		if err != nil || !mcpSameOrigin(issuer, parsed) || parsed.Path == "" || parsed.Path == "/" {
			return fail("oauth_endpoints", "Authorization and token endpoints must be HTTPS paths on the explicitly authorized issuer origin.")
		}
	}
	pass("authorization_server_metadata", "Issuer and OAuth endpoint origins match; endpoints were inspected, not invoked.")
	if !mcpHasValue(authorization.CodeChallengeMethods, "S256") {
		return fail("pkce", "Advertise and implement code_challenge_methods_supported including S256; hosted MCP clients require PKCE.")
	}
	pass("pkce", "S256 PKCE is advertised.")
	if !mcpHasValue(authorization.TokenEndpointAuthMethods, "none") {
		return fail("public_client", "Advertise token_endpoint_auth_methods_supported including none and configure a pre-registered public OAuth client ID; client-secret methods do not establish blank-secret support.")
	}
	if !mcpHasValue(authorization.ResponseTypesSupported, "code") || (len(authorization.GrantTypesSupported) != 0 && !mcpHasValue(authorization.GrantTypesSupported, "authorization_code")) {
		return fail("authorization_code", "Advertise response_types_supported including code and an authorization_code grant.")
	}
	if !mcpHasValue(authorization.ScopesSupported, "mcp:access") {
		return fail("scope", "Authorization metadata must advertise mcp:access. It grants route access, not per-tool read-only enforcement.")
	}
	pass("public_client", "Authorization-code public-client exchange is advertised; this check cannot verify a specific configured client ID.")
	if !authorization.IssuerResponseSupported {
		return fail("issuer_response", "Advertise authorization_response_iss_parameter_supported only after implementing matching iss in every success and error authorization response. This bounded flow requires issuer identification.")
	}
	pass("issuer_response", "Issuer identification is advertised; its actual callback response still needs an application test.")
	report.Ready = true
	return report, nil
}

func mcpHTTPSURL(raw string, originOnly bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.ContainsAny(raw, "?#\\\r\n\t ") || (originOnly && (u.Path != "" || u.RawPath != "")) {
		return nil, fmt.Errorf("unsafe HTTPS URL")
	}
	return u, nil
}

func mcpSameOrigin(a, b *url.URL) bool {
	return a != nil && b != nil && strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func mcpHasValue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func mcpDiscoveryGET(ctx context.Context, c *http.Client, location string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return c.Do(req)
}

func mcpReadMetadata(ctx context.Context, c *http.Client, location string, result any) error {
	response, err := mcpDiscoveryGET(ctx, c, location)
	if err != nil {
		return fmt.Errorf("Metadata HTTPS request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Metadata returned HTTP %d; redirects are not followed.", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, mcpMetadataLimit+1))
	if err != nil {
		return fmt.Errorf("Cannot read metadata: %w", err)
	}
	if len(data) > mcpMetadataLimit {
		return fmt.Errorf("Metadata exceeds the 64 KiB limit.")
	}
	// Reject ambiguous duplicate top-level fields while allowing unrelated OAuth
	// extensions. A truncated or concatenated document must never pass discovery.
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return fmt.Errorf("Metadata must be one JSON object.")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		keyName := strings.ToLower(name)
		if err != nil || !ok || seen[keyName] {
			return fmt.Errorf("Metadata contains invalid or repeated fields.")
		}
		seen[keyName] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("Metadata contains invalid JSON.")
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("Metadata contains incomplete JSON.")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("Metadata must contain exactly one JSON object.")
	}
	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("Metadata fields have invalid types.")
	}
	return nil
}

// Split authentication header items without treating commas inside quoted
// parameter values as challenge separators. Never copy arbitrary header text to
// diagnostics; it may have been generated by a credential-echoing server.
func mcpChallengeParameters(headers []string) (map[string]string, error) {
	parameters := make(map[string]string)
	for _, header := range headers {
		if len(header) > 8192 {
			return nil, fmt.Errorf("challenge too large")
		}
		quoted, escaped, start := false, false, 0
		var items []string
		for i, ch := range header {
			if escaped {
				escaped = false
				continue
			}
			if quoted && ch == '\\' {
				escaped = true
			} else if ch == '"' {
				quoted = !quoted
			} else if ch == ',' && !quoted {
				items = append(items, header[start:i])
				start = i + 1
			}
		}
		if quoted || escaped {
			return nil, fmt.Errorf("invalid challenge quoting")
		}
		items = append(items, header[start:])
		bearer := false
		for _, item := range items {
			item = strings.TrimSpace(item)
			if space := strings.IndexAny(item, " \t"); space >= 0 && !strings.Contains(item[:space], "=") && !strings.HasPrefix(strings.TrimSpace(item[space+1:]), "=") {
				bearer = strings.EqualFold(item[:space], "Bearer")
				item = strings.TrimSpace(item[space+1:])
			} else if !strings.Contains(item, "=") {
				bearer = strings.EqualFold(item, "Bearer")
				continue
			}
			if !bearer {
				continue
			}
			name, value, ok := strings.Cut(item, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if !ok || (name != "resource_metadata" && name != "scope") {
				continue
			}
			value = strings.TrimSpace(value)
			if strings.HasPrefix(value, "\"") {
				var decoded strings.Builder
				if len(value) < 2 || value[len(value)-1] != '"' {
					return nil, fmt.Errorf("invalid challenge parameter")
				}
				for i := 1; i < len(value)-1; i++ {
					if value[i] == '\\' {
						i++
						if i >= len(value)-1 {
							return nil, fmt.Errorf("invalid challenge parameter")
						}
					}
					decoded.WriteByte(value[i])
				}
				value = decoded.String()
			}
			if _, repeated := parameters[name]; repeated || value == "" {
				return nil, fmt.Errorf("challenge parameter missing or repeated")
			}
			parameters[name] = value
		}
	}
	if parameters["resource_metadata"] == "" {
		return nil, fmt.Errorf("metadata parameter missing")
	}
	return parameters, nil
}
