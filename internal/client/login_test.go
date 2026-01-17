package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetTokenPath(t *testing.T) {
	client := &LoginClient{}
	path := client.getTokenPath()

	// Should contain .tunn/token
	if !filepath.IsAbs(path) && path != ".tunn/token" {
		t.Errorf("Expected absolute path or fallback, got %s", path)
	}

	// Should end with token
	if filepath.Base(path) != "token" {
		t.Errorf("Expected path to end with 'token', got %s", path)
	}
}

func TestSaveAndLoadToken(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "tunn-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save original HOME and restore after test
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	// Test saving token
	client := &LoginClient{}
	testToken := "test-jwt-token-12345"

	err = client.saveToken(testToken)
	if err != nil {
		t.Fatalf("saveToken failed: %v", err)
	}

	// Verify file was created
	tokenPath := filepath.Join(tmpDir, ".tunn", "token")
	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		t.Error("Token file was not created")
	}

	// Test loading token
	loadedToken, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken failed: %v", err)
	}

	if loadedToken != testToken {
		t.Errorf("Loaded token '%s' != saved token '%s'", loadedToken, testToken)
	}
}

func TestLoadTokenNotFound(t *testing.T) {
	// Create a temporary empty directory
	tmpDir, err := os.MkdirTemp("", "tunn-test-empty-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save original HOME and restore after test
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	// Try to load token from empty home
	_, err = LoadToken()
	if err == nil {
		t.Error("Expected error when token file doesn't exist")
	}
}

func TestSaveTokenCreatesDirectory(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "tunn-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save original HOME and restore after test
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	// .tunn directory shouldn't exist yet
	tunnDir := filepath.Join(tmpDir, ".tunn")
	if _, err := os.Stat(tunnDir); !os.IsNotExist(err) {
		t.Fatal(".tunn directory already exists")
	}

	// Save token should create the directory
	client := &LoginClient{}
	err = client.saveToken("test-token")
	if err != nil {
		t.Fatalf("saveToken failed: %v", err)
	}

	// Verify directory was created
	if _, err := os.Stat(tunnDir); os.IsNotExist(err) {
		t.Error(".tunn directory was not created")
	}

	// Verify directory permissions (should be 0700)
	info, err := os.Stat(tunnDir)
	if err != nil {
		t.Fatalf("Failed to stat .tunn directory: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0700 {
		t.Errorf("Expected directory permissions 0700, got %o", perm)
	}
}

func TestLoginClientBasic(t *testing.T) {
	client := &LoginClient{
		ServerAddr: "localhost:8443",
		OIDCIssuer: "http://localhost:9000",
		SkipVerify: true,
	}

	if client.ServerAddr != "localhost:8443" {
		t.Errorf("Expected ServerAddr 'localhost:8443', got '%s'", client.ServerAddr)
	}
	if client.OIDCIssuer != "http://localhost:9000" {
		t.Errorf("Expected OIDCIssuer 'http://localhost:9000', got '%s'", client.OIDCIssuer)
	}
	if !client.SkipVerify {
		t.Error("Expected SkipVerify to be true")
	}
}
