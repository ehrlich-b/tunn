package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
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
	common.LogInfo("starting device flow login", "server", l.ServerAddr)

	// Reuse one transport across polls and replacement codes.
	copyClient := *l
	l = &copyClient
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
		_, _ = fmt.Fprintf(output, "\nYour code: %s\nExpires at: %s\n", deviceResp.UserCode, deviceResp.expiresAt.Local().Format("15:04:05 MST"))
		_, _ = fmt.Fprintf(output, "\nOpening browser to complete login...\n  %s\n\nVerify the code matches, then click Authorize.\nWaiting for authorization...\n", deviceResp.VerificationURIComplete)
		if l.OpenBrowser != nil {
			l.OpenBrowser(deviceResp.VerificationURIComplete)
		} else {
			l.openBrowser(deviceResp.VerificationURIComplete)
		}
		token, err = l.pollForToken(ctx, deviceResp)
		if errors.Is(err, errDeviceCodeExpired) {
			_, _ = fmt.Fprintln(output, "Login code expired or was used. Requesting a new code; use the new link below.")
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

	tokenPath, _ := l.getTokenPath() // saveToken already checked the path.
	common.LogInfo("login successful", "token_file", tokenPath)
	_, _ = fmt.Fprintln(output, "Logged in successfully!")

	return nil
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
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request returned status %d: %s", resp.StatusCode, string(body))
	}

	var deviceResp DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if deviceResp.DeviceCode == "" || deviceResp.UserCode == "" || deviceResp.ExpiresIn <= 0 || deviceResp.Interval < 0 {
		return nil, fmt.Errorf("invalid device code response")
	}
	deviceResp.expiresAt = time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
	if deviceResp.ExpiresAt != 0 {
		deviceResp.expiresAt = time.Unix(deviceResp.ExpiresAt, 0)
	}
	return &deviceResp, nil
}

var errDeviceCodeExpired = errors.New("device code expired or used")

// pollForToken polls the token endpoint until the user completes authentication
func (l *LoginClient) pollForToken(ctx context.Context, deviceResp *DeviceCodeResponse) (*TokenResponse, error) {
	interval := time.Duration(deviceResp.Interval) * time.Second
	if interval == 0 {
		interval = 3 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	expiresAt := deviceResp.expiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
	}
	pollCtx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()

	for {
		select {
		case <-pollCtx.Done():
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errDeviceCodeExpired
		case <-ticker.C:
			token, err := l.checkToken(pollCtx, deviceResp.DeviceCode)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if pollCtx.Err() != nil {
					return nil, errDeviceCodeExpired
				}
				return nil, err
			}

			// Check if still pending authorization
			if token.Error == "authorization_pending" {
				continue
			}

			// Got a valid token
			return token, nil
		}
	}
}

// checkToken attempts to exchange the device code for a token
func (l *LoginClient) checkToken(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("https://%s/api/device/token?code=%s", l.ServerAddr, url.QueryEscape(deviceCode))
	if !l.PolicyOwner {
		name, _ := os.Hostname()
		tokenURL += "&durable=1&name=" + url.QueryEscape(name)
	}

	client := l.httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Check for errors in response
	if tokenResp.Error != "" {
		if tokenResp.Error == "authorization_pending" {
			return &tokenResp, nil
		}
		if tokenResp.Error == "expired_token" {
			return nil, errDeviceCodeExpired
		}
		return nil, fmt.Errorf("token error: %s", tokenResp.Error)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response")
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

// LoadToken loads the saved access token
func LoadToken() (string, error) {
	tokenPath, err := (&LoginClient{}).getTokenPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no token found, please run 'tunn login' first")
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
