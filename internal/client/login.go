package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
)

// LoginClient handles the device code login flow
type LoginClient struct {
	ServerAddr string
	SkipVerify bool
}

// DeviceCodeResponse represents the response from the device authorization endpoint
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Run executes the device flow login process
func (l *LoginClient) Run(ctx context.Context) error {
	common.LogInfo("starting device flow login", "server", l.ServerAddr)

	// Step 1: Request device code
	deviceResp, err := l.requestDeviceCode()
	if err != nil {
		return fmt.Errorf("failed to request device code: %w", err)
	}

	// Step 2: Display URL and attempt to open browser
	fmt.Printf("\nYour code: %s\n", deviceResp.UserCode)
	fmt.Printf("\nOpening browser to complete login...\n")
	fmt.Printf("  %s\n", deviceResp.VerificationURIComplete)
	fmt.Printf("\nVerify the code matches, then click Authorize.\n")
	fmt.Printf("Waiting for authorization...\n")

	// Try to open browser
	l.openBrowser(deviceResp.VerificationURIComplete)

	// Step 3: Poll for token
	token, err := l.pollForToken(ctx, deviceResp)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	// Step 4: Save token to file
	if err := l.saveToken(token.AccessToken); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	common.LogInfo("login successful", "token_file", l.getTokenPath())
	fmt.Printf("Logged in successfully!\n")

	return nil
}

// requestDeviceCode requests a device code from the server
func (l *LoginClient) requestDeviceCode() (*DeviceCodeResponse, error) {
	deviceURL := fmt.Sprintf("https://%s/api/device/code", l.ServerAddr)

	client := l.httpClient()
	resp, err := client.Post(deviceURL, "application/json", nil)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request returned status %d: %s", resp.StatusCode, string(body))
	}

	var deviceResp DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &deviceResp, nil
}

// pollForToken polls the token endpoint until the user completes authentication
func (l *LoginClient) pollForToken(ctx context.Context, deviceResp *DeviceCodeResponse) (*TokenResponse, error) {
	interval := time.Duration(deviceResp.Interval) * time.Second
	if interval == 0 {
		interval = 3 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	timeout := time.After(time.Duration(deviceResp.ExpiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, fmt.Errorf("authentication timed out")
		case <-ticker.C:
			token, err := l.checkToken(deviceResp.DeviceCode)
			if err != nil {
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
func (l *LoginClient) checkToken(deviceCode string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("https://%s/api/device/token?code=%s", l.ServerAddr, url.QueryEscape(deviceCode))

	client := l.httpClient()
	resp, err := client.Get(tokenURL)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Check for errors in response
	if tokenResp.Error != "" {
		if tokenResp.Error == "authorization_pending" {
			return &tokenResp, nil
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
	tokenPath := l.getTokenPath()

	// Create directory if it doesn't exist
	dir := filepath.Dir(tokenPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}

	// Write token to file
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// getTokenPath returns the path to the token file
func (l *LoginClient) getTokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".tunn/token"
	}
	return filepath.Join(home, ".tunn", "token")
}

// LoadToken loads the saved access token
func LoadToken() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	tokenPath := filepath.Join(home, ".tunn", "token")
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
	if l.SkipVerify {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	return http.DefaultClient
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
	cmd.Start()
}
