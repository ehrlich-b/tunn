package status

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Origin accepts one operator-configured origin, never request-derived URLs.
func Origin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, errors.New("expected an http(s) origin without credentials, path, query or fragment")
	}
	u.Path = ""
	u.Scheme = strings.ToLower(u.Scheme)
	return u, nil
}
func ProbeClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type Collector struct {
	Store  *Store
	Origin *url.URL
	Client *http.Client
}

func (c *Collector) check(ctx context.Context, path string) bool {
	u := *c.Origin
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "tunn-status-probe")
	response, err := c.Client.Do(req)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}
func (c *Collector) Collect(ctx context.Context, now time.Time) error {
	sample := Sample{CheckedAt: now.UTC(), Health: c.check(ctx, "/healthz"), Ready: c.check(ctx, "/readyz")}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return c.Store.Record(ctx, sample)
}
func (c *Collector) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if err := c.Collect(ctx, time.Now()); err != nil && ctx.Err() == nil {
			slog.Error("status observation could not be stored")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
