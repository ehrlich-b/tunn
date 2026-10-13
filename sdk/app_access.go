package tunn

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AppInvitation is a short-lived enrollment handle, never an app credential.
// Configure the login authority independently before accepting a QR invitation.
type AppInvitation struct{ Authority, Hostname, Handle string }

func (i AppInvitation) String() string {
	return "App invitation for " + i.Hostname + " at " + i.Authority
}
func (i AppInvitation) GoString() string { return i.String() }

// AppDeviceHTTPClient omits browser cookies and refuses every redirect. Use it
// for enrollment and credential-bearing resource requests, with verified TLS.
// A custom transport may supply trusted CAs but must not disable TLS validation.
func AppDeviceHTTPClient(transport http.RoundTripper, timeout time.Duration) *http.Client {
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func appAuthority(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("an exact HTTPS login authority is required")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port), nil
}
func appHostname(host string) bool {
	if len(host) > 253 || host == "" || host != strings.ToLower(host) || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

// ParseAppInvitation rejects an untrusted QR authority before any network I/O.
// The authority argument must come from trusted app configuration, never the QR.
func ParseAppInvitation(authority, qr string) (AppInvitation, error) {
	trusted, err := appAuthority(authority)
	if err != nil {
		return AppInvitation{}, err
	}
	u, err := url.Parse(qr)
	if err != nil || len(qr) > 2048 || u.Scheme != "https" || u.User != nil || u.Path != "/pair/app-device" || u.RawQuery != "" {
		return AppInvitation{}, fmt.Errorf("invalid app invitation")
	}
	origin, err := appAuthority("https://" + u.Host)
	if err != nil || origin != trusted {
		return AppInvitation{}, fmt.Errorf("invitation uses a different login authority")
	}
	values, err := url.ParseQuery(u.Fragment)
	if err != nil || len(values) != 2 || len(values["invitation"]) != 1 || len(values["hostname"]) != 1 {
		return AppInvitation{}, fmt.Errorf("invalid invitation fragment")
	}
	handle, host := values.Get("invitation"), values.Get("hostname")
	bytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(handle, "tunn_inv_"))
	if !strings.HasPrefix(handle, "tunn_inv_") || err != nil || len(bytes) != 32 || len(handle) != 52 || !appHostname(host) {
		return AppInvitation{}, fmt.Errorf("invalid invitation scope or handle")
	}
	return AppInvitation{Authority: strings.TrimSuffix(authority, "/"), Hostname: host, Handle: handle}, nil
}

// SetAppAuthorization applies a device credential only to its exact HTTPS host.
// It preserves upstream Authorization and works on HTTP WebSocket upgrades.
// Persist credentials in the OS credential vault; do not log this argument.
// Use AppDeviceHTTPClient so a response cannot redirect this header elsewhere.
func SetAppAuthorization(r *http.Request, hostname, credential string) error {
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.User != nil || r.URL.Hostname() != hostname || !appHostname(hostname) || (r.Host != "" && requestAppHostname(r.Host) != hostname) {
		return fmt.Errorf("app credential requires its exact HTTPS hostname")
	}
	secret, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(credential, "tunn_app_"))
	if !strings.HasPrefix(credential, "tunn_app_") || err != nil || len(secret) != 32 || len(credential) != 52 {
		return fmt.Errorf("invalid app credential")
	}
	for name := range r.Header {
		if strings.EqualFold(name, "Tunn-Authorization") {
			return fmt.Errorf("request already has a tunn authorization field")
		}
	}
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.Header.Set("Tunn-Authorization", "Bearer "+credential)
	return nil
}
func requestAppHostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
