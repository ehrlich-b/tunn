package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetTokenPath(t *testing.T) {
	client := &LoginClient{}
	path, err := client.getTokenPath()
	if err != nil {
		t.Fatal(err)
	}

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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Restore the test process environment automatically.
	t.Setenv("HOME", tmpDir)

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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Restore the test process environment automatically.
	t.Setenv("HOME", tmpDir)

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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Restore the test process environment automatically.
	t.Setenv("HOME", tmpDir)

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
		Insecure:   true,
	}

	if client.ServerAddr != "localhost:8443" {
		t.Errorf("Expected ServerAddr 'localhost:8443', got '%s'", client.ServerAddr)
	}
	if !client.Insecure {
		t.Error("Expected Insecure to be true")
	}
}

func TestLoginTokenUsesIsolatedConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(configDirectoryEnvironment, dir)
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("old-test-token"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := (&LoginClient{}).saveToken("replacement-test-token"); err != nil {
		t.Fatal(err)
	}
	got, err := LoadToken()
	if err != nil || got != "replacement-test-token" {
		t.Fatalf("isolated login token = %q, %v", got, err)
	}
	for path, want := range map[string]os.FileMode{dir: 0700, path: 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("permissions for %s: info=%v, error=%v, want %o", path, info, err, want)
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, ".token.*.tmp"))
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary credential files remain: %v, %v", files, err)
	}
}

func TestLoginTokenReplacesSymlinkWithoutOverwritingTarget(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(configDirectoryEnvironment, dir)
	target := filepath.Join(dir, "other-file")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "token")); err != nil {
		t.Fatal(err)
	}
	if err := (&LoginClient{}).saveToken("test-token"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("symlink target was overwritten: %q, %v", data, err)
	}
	info, err := os.Lstat(filepath.Join(dir, "token"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("replacement is not a private regular file: %v, %v", info, err)
	}
}

func TestLoginRejectsRelativeConfigDirectory(t *testing.T) {
	t.Setenv(configDirectoryEnvironment, "relative/config")
	if err := (&LoginClient{}).saveToken("test-token"); err == nil {
		t.Fatal("saving login token accepted a relative directory")
	}
	if _, err := LoadToken(); err == nil {
		t.Fatal("loading login token accepted a relative directory")
	}
}
