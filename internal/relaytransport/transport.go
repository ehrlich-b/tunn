// Package relaytransport provides proxy-aware connections to the public relay.
// Origin and node-to-node connections intentionally use their own transports.
package relaytransport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/proxy"
)

// ProxyFromEnvironment follows HTTP(S)_PROXY and NO_PROXY, with ALL_PROXY as
// the fallback. Both uppercase and lowercase spellings are supported.
func ProxyFromEnvironment(r *http.Request) (*url.URL, error) {
	cfg := httpproxy.FromEnvironment()
	all := os.Getenv("ALL_PROXY")
	if all == "" {
		all = os.Getenv("all_proxy")
	}
	if cfg.HTTPSProxy == "" {
		cfg.HTTPSProxy = all
	}
	if cfg.HTTPProxy == "" {
		cfg.HTTPProxy = all
	}
	return cfg.ProxyFunc()(r.URL)
}

// Transport keeps TLS verification enabled unless explicitly disabled by the
// caller, and negotiates HTTP/2 inside HTTP CONNECT or SOCKS proxy tunnels.
func Transport(insecure bool) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = ProxyFromEnvironment
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
	tr.ForceAttemptHTTP2 = true
	return tr
}

// DialContext is the gRPC transport dialer. The relay hostname is passed to the
// proxy unchanged so proxy-only clients do not need local relay DNS resolution.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialContext(ctx, network, address, (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext)
}

// Dialer wraps an embedded network dialer with the default proxy policy.
func Dialer(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialContext(ctx, network, address, dial)
	}
}

func dialContext(ctx context.Context, network, address string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	proxyURL, err := ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: address}})
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		return dial(ctx, network, address)
	}
	if proxyURL.Scheme == "socks5" || proxyURL.Scheme == "socks5h" {
		// x/net/proxy uses the same remote DNS behavior for both spellings.
		socksURL := *proxyURL
		socksURL.Scheme = "socks5"
		d, err := proxy.FromURL(&socksURL, contextDialer{dial})
		if err != nil {
			return nil, err
		}
		return d.(proxy.ContextDialer).DialContext(ctx, network, address)
	}
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported relay proxy scheme %q", proxyURL.Scheme)
	}
	proxyAddress := proxyURL.Host
	if proxyURL.Port() == "" {
		port := "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
		proxyAddress = net.JoinHostPort(proxyURL.Hostname(), port)
	}
	conn, err := dial(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		_ = conn.SetDeadline(deadline)
	}
	if proxyURL.Scheme == "https" {
		secured := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname(), MinVersion: tls.VersionTLS12})
		if err := secured.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS to relay proxy: %w", err)
		}
		conn = secured
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		value := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+value)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("CONNECT to relay proxy: %w", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("CONNECT response from relay proxy: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay proxy CONNECT returned HTTP %d", resp.StatusCode)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop()
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

type contextDialer struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func (d contextDialer) Dial(network, address string) (net.Conn, error) {
	return d.dial(context.Background(), network, address)
}
func (d contextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
