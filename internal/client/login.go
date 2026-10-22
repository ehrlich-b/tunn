package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
	"github.com/ehrlich-b/tunn/internal/terminal"
)

// LoginClient handles the device code login flow
type LoginClient struct {
	PolicyOwner bool // Explicit account-management login; separate from device credentials
	ServerAddr  string
	Insecure    bool
	HTTPClient  *http.Client // Optional embedded or test transport.
	Output      io.Writer
	OpenBrowser func(string) // Optional embedded or test browser opener.
}

// DeviceCodeResponse represents the response from the device authorization endpoint
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	ExpiresAt               int64  `json:"expires_at,omitempty"`
	Interval                int    `json:"interval"`
	expiresAt               time.Time
}

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Run executes the device flow login process
func (l *LoginClient) Run(ctx context.Context) error {
	common.LogInfo("starting device flow login")
	origin, err := canonicalCredentialServer(l.ServerAddr)
	if err != nil {
		return err
	}
	if _, err := configDirectory(); err != nil {
		return err
	}

	// Reuse one transport across polls and replacement codes.
	copyClient := *l
	l = &copyClient
	l.ServerAddr = strings.TrimPrefix(origin, "https://")
	if l.HTTPClient == nil {
		transport := relaytransport.Transport(l.Insecure)
		defer transport.CloseIdleConnections()
		l.HTTPClient = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	}
	output := l.Output
	if output == nil {
		output = os.Stdout
	}
	var token *TokenResponse
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		deviceResp, err := l.requestDeviceCode(ctx)
		if err != nil {
			return fmt.Errorf("failed to request device code: %w", err)
		}
		link := deviceResp.VerificationURIComplete
		if link == "" {
			link = deviceResp.VerificationURI
		}
		if parsed, err := url.Parse(link); err == nil {
			query := parsed.Query()
			safeQuery := url.Values{}
			for _, name := range []string{"code", "user_code"} {
				if query.Get(name) == deviceResp.UserCode {
					safeQuery.Set(name, deviceResp.UserCode)
				}
			}
			parsed.RawQuery = safeQuery.Encode()
			parsed.Fragment = ""
			parsed.User = nil
			link = parsed.String()
		} else {
			link = ""
		}
		_, _ = fmt.Fprintf(output, "\nOpen your browser to sign in\n%s\n\nCode: %s\nExpires at: %s\nMatch this code, then authorize.\nWaiting for sign-in…\n", terminal.Safe(link), terminal.Safe(deviceResp.UserCode), deviceResp.expiresAt.Local().Format("15:04:05 MST"))
		if l.OpenBrowser != nil {
			l.OpenBrowser(deviceResp.VerificationURIComplete)
		} else {
			l.openBrowser(deviceResp.VerificationURIComplete)
		}
		token, err = l.pollForToken(ctx, deviceResp)
		if errors.Is(err, errDeviceCodeExpired) {
			_, _ = fmt.Fprintln(output, "Code expired. Requesting a new code.")
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get token: %w", err)
		}
		break
	}

	// Step 4: Save token to file
	if err := l.saveCredentials(token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	identity, _ := common.ExtractEmailFromJWT(token.AccessToken)
	if identity != "" {
		_, _ = fmt.Fprintln(output, "Signed in as "+terminal.Safe(identity))
	} else {
		_, _ = fmt.Fprintln(output, "Signed in")
	}
	if l.PolicyOwner {
		_, _ = fmt.Fprintln(output, "\ntunn policy --help")
	} else {
		_, _ = fmt.Fprintln(output, "\ntunn 3000")
	}

	if !l.PolicyOwner && token.RefreshToken == "" {
		_, _ = fmt.Fprintln(output, "Warning: this relay issued a login that cannot renew; always-on tunnels stop when it expires. Run tunn login again after the relay is updated.")
	}

	return nil
}

// DeviceCodeHTTPError retains the HTTP status for login failure guidance.
type DeviceCodeHTTPError struct {
	StatusCode int
}

func (e *DeviceCodeHTTPError) Error() string {
	return fmt.Sprintf("request returned status %d", e.StatusCode)
}

// requestDeviceCode requests a device code from the server
func (l *LoginClient) requestDeviceCode(ctx context.Context) (*DeviceCodeResponse, error) {
	purpose := "publisher"
	if l.PolicyOwner {
		purpose = "management"
	}
	deviceURL := fmt.Sprintf("https://%s/api/device/code?purpose=%s", l.ServerAddr, purpose)

	client := l.httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceURL, nil)
	if err != nil {
		return nil, errors.New("invalid sign-in server configuration")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &loginConnectionError{cause: err, message: "could not reach sign-in server"}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &DeviceCodeHTTPError{StatusCode: resp.StatusCode}
	}

	var deviceResp DeviceCodeResponse
	if err := decodeLoginResponse(resp.Body, &deviceResp); err != nil {
		return nil, errors.New("invalid device code response")
	}

	if deviceResp.DeviceCode == "" || deviceResp.UserCode == "" || deviceResp.ExpiresIn <= 0 || deviceResp.Interval < 0 || int64(deviceResp.Interval) > maxLoginSeconds || int64(deviceResp.ExpiresIn) > maxLoginSeconds {
		return nil, fmt.Errorf("invalid device code response")
	}
	deviceResp.expiresAt = time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
	if deviceResp.ExpiresAt != 0 {
		deviceResp.expiresAt = time.Unix(deviceResp.ExpiresAt, 0)
	}
	return &deviceResp, nil
}

var errDeviceCodeExpired = errors.New("device code expired or used")

// Retry delays double up to 30 seconds, but never undercut the server interval.
const maxLoginBackoff = 30 * time.Second
const maxLoginSeconds = int64((1<<63 - 1) / time.Second)

type loginConnectionError struct {
	cause   error
	message string
}

func (e *loginConnectionError) Error() string { return e.message }
func (e *loginConnectionError) Unwrap() error { return e.cause }

type loginRetryError struct{ after time.Duration }

func (*loginRetryError) Error() string { return "sign-in server temporarily unavailable" }

func transientLoginTransport(err error) bool {
	var network net.Error
	return (errors.As(err, &network) && (network.Timeout() || network.Temporary())) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)
}

func decodeLoginResponse(body io.Reader, dest any) error {
	data, err := io.ReadAll(io.LimitReader(body, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("sign-in response too large")
	}
	return json.Unmarshal(data, dest)
}

// pollForToken keeps one code and its original deadline through relay outages.
func (l *LoginClient) pollForToken(ctx context.Context, deviceResp *DeviceCodeResponse) (*TokenResponse, error) {
	if deviceResp.Interval < 0 || int64(deviceResp.Interval) > maxLoginSeconds {
		return nil, errors.New("invalid sign-in interval")
	}
	interval := time.Duration(deviceResp.Interval) * time.Second
	if interval == 0 {
		interval = 3 * time.Second
	}
	delay, backoff := interval, interval
	expiresAt := deviceResp.expiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
	}
	pollCtx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()
	warned := false
	for {
		timer := time.NewTimer(delay)
		select {
		case <-pollCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errDeviceCodeExpired
		case <-timer.C:
		}
		// A deadline and timer can become ready together; never exchange an expired code.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !time.Now().Before(expiresAt) {
			return nil, errDeviceCodeExpired
		}
		token, err := l.checkToken(pollCtx, deviceResp.DeviceCode)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if pollCtx.Err() != nil || !time.Now().Before(expiresAt) {
			return nil, errDeviceCodeExpired
		}
		if err != nil {
			var retry *loginRetryError
			if !errors.As(err, &retry) {
				return nil, err
			}
			if !warned {
				output := l.Output
				if output == nil {
					output = os.Stdout
				}
				_, _ = fmt.Fprintln(output, "Sign-in temporarily unavailable. Retrying until this code expires; Ctrl+C to cancel.")
				warned = true
			}
			ceiling := max(maxLoginBackoff, interval)
			if backoff >= ceiling/2 {
				backoff = ceiling
			} else {
				backoff *= 2
			}
			delay = max(backoff, retry.after)
			continue
		}
		if token.Error == "slow_down" {
			if interval > time.Duration(1<<63-1)-5*time.Second {
				return nil, errors.New("invalid sign-in interval")
			}
			interval += 5 * time.Second
		}
		if token.Error == "authorization_pending" || token.Error == "slow_down" {
			delay, backoff = interval, interval
			continue
		}
		return token, nil
	}
}

// checkToken returns only fixed diagnostics; responses and request URLs contain secrets.
func (l *LoginClient) checkToken(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("https://%s/api/device/token?code=%s", l.ServerAddr, url.QueryEscape(deviceCode))
	if !l.PolicyOwner {
		name, _ := os.Hostname()
		tokenURL += "&durable=1&name=" + url.QueryEscape(name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return nil, errors.New("invalid sign-in server configuration")
	}
	resp, err := l.httpClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if transientLoginTransport(err) {
			return nil, &loginRetryError{}
		}
		return nil, &loginConnectionError{cause: err, message: "sign-in connection failed; check server and TLS configuration"}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 && resp.StatusCode <= 599 {
		var after time.Duration
		if seconds, err := time.ParseDuration(resp.Header.Get("Retry-After") + "s"); err == nil && seconds > 0 {
			after = seconds
		} else if date, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil {
			after = max(0, time.Until(date))
		}
		return nil, &loginRetryError{after: after}
	}
	var tokenResp TokenResponse
	if err := decodeLoginResponse(resp.Body, &tokenResp); err != nil {
		if transientLoginTransport(err) {
			return nil, &loginRetryError{}
		}
		return nil, errors.New("invalid sign-in token response")
	}
	if tokenResp.Error != "" {
		switch tokenResp.Error {
		case "authorization_pending", "slow_down":
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest {
				return &tokenResp, nil
			}
		case "expired_token":
			return nil, errDeviceCodeExpired
		case "invalid_grant":
			return nil, errors.New("sign-in rejected: invalid grant")
		case "access_denied", "authorization_declined":
			return nil, errors.New("sign-in denied")
		case "invalid_client", "unauthorized_client", "invalid_request", "unsupported_grant_type":
			return nil, errors.New("sign-in rejected: check client and server configuration")
		}
		return nil, errors.New("sign-in rejected by server")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sign-in request returned status %d", resp.StatusCode)
	}
	if tokenResp.AccessToken == "" {
		return nil, errors.New("no access token in response")
	}
	return &tokenResp, nil
}

// saveToken saves the access token to a file
func (l *LoginClient) saveToken(token string) error {
	tokenPath, err := l.getTokenPath()
	if err != nil {
		return err
	}
	_, err = writePrivateTokenFile(filepath.Dir(tokenPath), filepath.Base(tokenPath), token)
	return err
}

// getTokenPath returns the path to the token file
func (l *LoginClient) getTokenPath() (string, error) {
	dir, err := configDirectory()
	if err != nil {
		return "", err
	}
	if l.PolicyOwner {
		return filepath.Join(dir, policyOwnerFilename), nil
	}
	return filepath.Join(dir, "token"), nil
}

// ErrNotLoggedIn means no publisher login is saved in the config directory.
var ErrNotLoggedIn = errors.New("no token found, please run 'tunn login' first")

// LoadToken loads the saved access token
func LoadToken() (string, error) {
	tokenPath, err := (&LoginClient{}).getTokenPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNotLoggedIn
		}
		return "", fmt.Errorf("failed to read token: %w", err)
	}

	return string(data), nil
}

// httpClient returns an HTTP client, optionally skipping TLS verification
func (l *LoginClient) httpClient() *http.Client {
	hc := l.HTTPClient
	if hc == nil {
		hc = &http.Client{Transport: relaytransport.Transport(l.Insecure), Timeout: 30 * time.Second}
	}
	if l.PolicyOwner {
		guarded := *hc
		guarded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &guarded
	}
	return hc
}

// openBrowser attempts to open the URL in the default browser
func (l *LoginClient) openBrowser(url string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return
	}

	// Run in background, ignore errors (user can manually open URL)
	_ = cmd.Start()
}
