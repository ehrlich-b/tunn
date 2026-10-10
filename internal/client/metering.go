package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ManagementClient talks to the relay's owner API. The caller supplies the owner
// JWT separately from any consumer grant; redirects never receive credentials.
type ManagementClient struct {
	ServerURL  string
	OwnerToken string
	HTTPClient *http.Client
}

func (c *ManagementClient) Call(ctx context.Context, method, endpoint, operation string, input any) (json.RawMessage, error) {
	base := c.ServerURL
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("server must be an HTTP(S) origin without credentials")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme != "https" && (u.Scheme != "http" || host != "localhost" && (ip == nil || !ip.IsLoopback())) {
		return nil, fmt.Errorf("owner credentials require HTTPS (HTTP is allowed only on loopback)")
	}
	if endpoint != "" && !validManagementEndpoint(endpoint) {
		return nil, fmt.Errorf("invalid endpoint name")
	}
	u.Path = "/api/endpoints/" + endpoint + "/" + strings.SplitN(operation, "?", 2)[0]
	if endpoint == "" {
		if method != http.MethodGet || strings.SplitN(operation, "?", 2)[0] != "usage" && operation != "grants" {
			return nil, fmt.Errorf("endpoint required for this operation")
		}
		u.Path = "/api/" + strings.SplitN(operation, "?", 2)[0]
	}
	if parts := strings.SplitN(operation, "?", 2); len(parts) == 2 {
		u.RawQuery = parts[1]
	}
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.OwnerToken))
	req.Header.Set("Content-Type", "application/json")
	hc := http.DefaultClient
	if c.HTTPClient != nil {
		hc = c.HTTPClient
	}
	copyClient := *hc
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := copyClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	const maxExport = 128 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxExport+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxExport {
		return nil, fmt.Errorf("usage export too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("owner API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if len(data) > 0 && !json.Valid(data) {
		return nil, fmt.Errorf("owner API returned invalid JSON")
	}
	return json.RawMessage(data), nil
}
func validManagementEndpoint(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
