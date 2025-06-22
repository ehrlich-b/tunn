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
	ID     string
	To     string
	Domain string
	Token  string
}

// Run starts the client
func (c *Client) Run() {
	if c.ID == "" {
		c.ID = common.RandID(7)
	}
	common.LogInfo("client starting", "id", c.ID)

	// Create an HTTP client with HTTP/2 support
	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Note: In production, use proper certificate validation
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
				//InsecureSkipVerify: true, // Make this configurable
			},
		},
		Director: func(req *http.Request) {
			// point at the local server
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host

			// strip the /proxy/<id>/ prefix
			if strings.HasPrefix(req.URL.Path, prefix) {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, prefix)
			}
			if !strings.HasPrefix(req.URL.Path, "/") {
				req.URL.Path = "/" + req.URL.Path
			}

			// make the Host header match the upstream (optional but polite)
			req.Host = req.URL.Host
		},
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// context.Canceled is a common error when the client closes the connection
		// before the response is fully written. It's not a server-side error.
		if err == context.Canceled {
			common.LogDebug("request canceled by remote", "remote_addr", r.RemoteAddr)
			return
		}
		common.LogError("reverse proxy error", "request_url", r.URL.String(), "upstream", upstream.String(), "error", err)
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}

	srv := &http.Server{
		Handler: proxy,
	}

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		common.LogError("proxy server error", "error", err)
		os.Exit(1)
	}
}
