package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"os"
	"strings"

	"github.com/aojea/h2rev2"
	"golang.org/x/net/http2"

	"github.com/ehrlich-b/tunn/internal/common"
)

// Client represents the tunnel client
type Client struct {
	ID         string
	To         string
	Domain     string
	Token      string
	SkipVerify bool
}

// ValidateConfig validates the client configuration
func (c *Client) ValidateConfig() error {
	if c.Token == "" {
		return errors.New("token is required")
	}
	if c.Domain == "" {
		return errors.New("domain is required")
	}
	if c.To == "" {
		return errors.New("target URL is required")
	}

	// Normalize and validate target URL
	normalized, err := c.NormalizeTargetURL(c.To)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	c.To = normalized

	return nil
}

// NormalizeTargetURL converts various input formats to a full URL
// Accepts: "8000", "localhost:8000", "http://localhost:8000"
// Always returns: "http://localhost:8000" format
func (c *Client) NormalizeTargetURL(input string) (string, error) {
	if input == "" {
		return "", errors.New("empty target")
	}

	// If it's already a full URL, validate and return
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		_, err := neturl.Parse(input)
		if err != nil {
			return "", err
		}
		return input, nil
	}

	// Check if it's just a port number
	if strings.Contains(input, ":") {
		// Format: "host:port"
		return "http://" + input, nil
	}

	// Check if it's just a port number (digits only)
	for _, char := range input {
		if char < '0' || char > '9' {
			return "", fmt.Errorf("invalid format: %s (expected port, host:port, or full URL)", input)
		}
	}

	// It's just a port number
	return "http://localhost:" + input, nil
}

// GetPublicURL returns the public URL for this tunnel
func (c *Client) GetPublicURL() string {
	if c.ID == "" {
		return ""
	}
	return fmt.Sprintf("https://%s.%s", c.ID, c.Domain)
}

// GenerateIDIfEmpty generates a random ID if one is not set
func (c *Client) GenerateIDIfEmpty() {
	if c.ID == "" {
		c.ID = common.RandID(7)
	}
}

// Run starts the client
func (c *Client) Run() {
	c.GenerateIDIfEmpty()

	// Validate and normalize configuration
	if err := c.ValidateConfig(); err != nil {
		common.LogError("invalid configuration", "error", err)
		os.Exit(1)
	}

	tunnelURL := c.GetPublicURL()
	common.LogInfo("client starting", "id", c.ID)
	common.LogInfo("tunnel URL", "url", tunnelURL)

	// Create an HTTP client with HTTP/2 support
	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.SkipVerify,
			},
		},
	}

	// Add authorization header to requests
	baseURL := "https://" + c.Domain
	common.LogInfo("client announcing", "url", baseURL)

	// Create a request interceptor to add Authorization header
	originalTransport := client.Transport
	client.Transport = &common.LogAuthTransport{
		Transport: originalTransport,
		Token:     c.Token,
	}

	// Create the listener with proper URL
	ln, err := h2rev2.NewListener(client, baseURL, c.ID)
	if err != nil {
		common.LogError("failed to create listener", "error", err)
		os.Exit(1)
	}
	defer ln.Close()

	pubURL := fmt.Sprintf("https://%s.%s", c.ID, c.Domain)

	upstream, err := neturl.Parse(c.To)
	if err != nil {
		common.LogError("invalid upstream URL", "url", c.To, "error", err)
		os.Exit(1)
	}
	common.LogInfo("tunnel established", "public_url", pubURL, "upstream", upstream.Host)
	prefix := "/proxy/" + c.ID + "/"
	proxy := &httputil.ReverseProxy{
		FlushInterval: -1,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.SkipVerify,
			},
		},
		Director: func(req *http.Request) {
			originalPath := req.URL.Path

			// point at the local server
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host

			// strip the /proxy/<id>/ prefix
			if strings.HasPrefix(req.URL.Path, prefix) {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, prefix)
			}

			// Ensure path starts with /
			if req.URL.Path == "" || !strings.HasPrefix(req.URL.Path, "/") {
				req.URL.Path = "/" + req.URL.Path
			}

			// make the Host header match the upstream (optional but polite)
			req.Host = req.URL.Host

			common.LogDebug("proxying request",
				"from", originalPath,
				"to", req.URL.String(),
				"method", req.Method)
		},
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// context.Canceled is a common error when the client closes the connection
		// before the response is fully written. It's not a server-side error.
		if err == context.Canceled {
			common.LogDebug("request canceled by remote", "remote_addr", r.RemoteAddr)
			return
		}
		common.LogError("reverse proxy error",
			"request_url", r.URL.String(),
			"upstream", upstream.String(),
			"error", err,
			"method", r.Method)
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}

	srv := &http.Server{
		Handler: proxy,
	}

	common.LogInfo("client proxy listening for connections from host")
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		common.LogError("proxy server error", "error", err)
		os.Exit(1)
	}
}
