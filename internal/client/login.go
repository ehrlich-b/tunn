package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
)

// LoginClient handles the OAuth Device Authorization Grant flow
type LoginClient struct {
	ServerAddr string
	OIDCIssuer string
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
	common.LogInfo("starting device flow login", "issuer", l.OIDCIssuer)

	// Step 1: Request device code
	deviceResp, err := l.requestDeviceCode()
	if err != nil {
		return fmt.Errorf("failed to request device code: %w", err)
	}

	// Step 2: Display user code and verification URL
	fmt.Printf("\n")
	fmt.Printf("To authenticate, visit:\n")
	fmt.Printf("  %s\n", deviceResp.VerificationURIComplete)
	fmt.Printf("\n")
	fmt.Printf("Or go to %s and enter code: %s\n", deviceResp.VerificationURI, deviceResp.UserCode)
	fmt.Printf("\n")
	fmt.Printf("Waiting for authentication...\n")

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
	fmt.Printf("\nLogin successful! Token saved to %s\n", l.getTokenPath())

	return nil
}

// requestDeviceCode requests a device code from the OIDC provider
func (l *LoginClient) requestDeviceCode() (*DeviceCodeResponse, error) {
	deviceURL := l.OIDCIssuer + "/device/code"

	data := url.Values{}
	data.Set("client_id", "tunn")
	data.Set("scope", "openid email")

	resp, err := http.PostForm(deviceURL, data)
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
	tokenURL := l.OIDCIssuer + "/token"
	interval := time.Duration(deviceResp.Interval) * time.Second
	if interval == 0 {
		interval = 5 * time.Second
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
			token, err := l.checkToken(tokenURL, deviceResp.DeviceCode)
			if err == nil {
				return token, nil
			}

			// Check if error is authorization_pending (expected while waiting)
			if token != nil && token.Error == "authorization_pending" {
				continue
			}

			// Any other error is fatal
			return nil, err
		}
	}
}

// checkToken attempts to exchange the device code for a token
func (l *LoginClient) checkToken(tokenURL, deviceCode string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCode)
	data.Set("client_id", "tunn")

	resp, err := http.PostForm(tokenURL, data)
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
