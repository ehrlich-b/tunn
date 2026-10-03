package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
)

// GrantClient uses the owner control API. Credentials never appear in URLs or
// redirect requests; callers decide where the one-time credential is saved.
type GrantClient struct {
	BaseURL    string
	OwnerToken string
	HTTPClient *http.Client
}

func (c *GrantClient) request(ctx context.Context, method, path string, body any, result any) error {
	base, err := url.Parse(c.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return fmt.Errorf("grant server must be an HTTPS origin")
	}
	if strings.TrimSpace(c.OwnerToken) == "" {
		return fmt.Errorf("owner access token required")
	}
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.BaseURL, "/")+path, &encoded)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.OwnerToken)
	req.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if c.HTTPClient != nil {
		*httpClient = *c.HTTPClient
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("grant API request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// Server error bodies are intentionally omitted: a misconfigured origin
		// must not echo owner or grant credentials into logs.
		return fmt.Errorf("grant API returned HTTP %d", response.StatusCode)
	}
	if result == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(result)
}

func (c *GrantClient) Create(ctx context.Context, endpoint, label string, ttl time.Duration, limit int64) (*store.Grant, string, error) {
	var out struct {
		Grant *store.Grant `json:"grant"`
		Token string       `json:"token"`
	}
	err := c.request(ctx, http.MethodPost, "/api/grants", struct {
		Endpoint     string `json:"endpoint"`
		Label        string `json:"label"`
		TTLSeconds   int64  `json:"ttl_seconds"`
		RequestLimit int64  `json:"request_limit"`
	}{endpoint, label, int64(ttl / time.Second), limit}, &out)
	if err != nil {
		return nil, "", err
	}
	if out.Grant == nil || out.Grant.ID == "" || !strings.HasPrefix(out.Token, store.GrantTokenPrefix) {
		return nil, "", fmt.Errorf("invalid grant creation response")
	}
	return out.Grant, out.Token, nil
}

func (c *GrantClient) List(ctx context.Context, endpoint string) ([]store.Grant, error) {
	var out struct {
		Grants []store.Grant `json:"grants"`
	}
	err := c.request(ctx, http.MethodGet, "/api/grants?endpoint="+url.QueryEscape(endpoint), nil, &out)
	return out.Grants, err
}

func (c *GrantClient) Revoke(ctx context.Context, id string) error {
	if id == "" || strings.ContainsAny(id, "/?#") {
		return fmt.Errorf("invalid grant ID")
	}
	return c.request(ctx, http.MethodDelete, "/api/grants/"+url.PathEscape(id), nil, nil)
}
