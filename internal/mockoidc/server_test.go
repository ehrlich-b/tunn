package mockoidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDiscoveryEndpoint(t *testing.T) {
	srv, err := New(Config{
		Addr:   ":0",
		Issuer: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	srv.handleDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var discovery map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&discovery); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if discovery["issuer"] != srv.issuer {
		t.Errorf("Expected issuer %s, got %v", srv.issuer, discovery["issuer"])
	}

	if discovery["device_authorization_endpoint"] == nil {
		t.Error("Expected device_authorization_endpoint in discovery")
	}
}

func TestDeviceCodeFlow(t *testing.T) {
	srv, err := New(Config{
		Addr:   ":0",
		Issuer: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Step 1: Request device code
	req := httptest.NewRequest(http.MethodPost, "/oauth/device/code", nil)
	w := httptest.NewRecorder()

	srv.handleDeviceCode(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var deviceResp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&deviceResp); err != nil {
		t.Fatalf("Failed to decode device response: %v", err)
	}

	deviceCode := deviceResp["device_code"].(string)
	userCode := deviceResp["user_code"].(string)

	if deviceCode == "" || userCode == "" {
		t.Fatal("Expected device_code and user_code")
	}

	// Step 2: Poll for token (should get authorization_pending)
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)

	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()

	srv.handleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 (pending), got %d", w.Code)
	}

	var errorResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errorResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errorResp["error"] != "authorization_pending" {
		t.Errorf("Expected authorization_pending, got %s", errorResp["error"])
	}

	// Step 3: Simulate user authorization
	srv.mu.Lock()
	if data, ok := srv.deviceCodes[deviceCode]; ok {
		data.Authorized = true
		data.UserEmail = "test@example.com"
	}
	srv.mu.Unlock()

	// Step 4: Poll again for token (should succeed)
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()

	srv.handleToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	if tokenResp["access_token"] == nil {
		t.Error("Expected access_token in response")
	}

	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("Expected token_type Bearer, got %v", tokenResp["token_type"])
	}
}

func TestGenerateUserCode(t *testing.T) {
	code := generateUserCode()
	if len(code) != 9 { // 4 + hyphen + 4
		t.Errorf("Expected user code length 9, got %d", len(code))
	}

	if code[4] != '-' {
		t.Error("Expected hyphen at position 4")
	}
}
