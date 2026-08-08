package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const endpointTokenPrefix = "tunn_ep_"

const configDirectoryEnvironment = "TUNN_CONFIG_DIR"

// GenerateEndpointToken creates a high-entropy endpoint-scoped bearer token
// and returns both its plaintext representation and SHA-256 digest. Only the
// digest is sent to the tunn relay.
func GenerateEndpointToken() (token string, digest []byte, err error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", nil, fmt.Errorf("generate endpoint token: %w", err)
	}

	token = endpointTokenPrefix + base64.RawURLEncoding.EncodeToString(random)
	hash := sha256.Sum256([]byte(token))
	return token, hash[:], nil
}

// SaveEndpointToken stores a token outside the repository in the user's tunn
// configuration directory. The returned path is suitable for CLI guidance.
func SaveEndpointToken(tunnelID, token string) (string, error) {
	name, err := safeEndpointName(tunnelID)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(token, endpointTokenPrefix) {
		return "", fmt.Errorf("invalid endpoint token format")
	}

	dir, err := endpointTokenDirectory()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create endpoint token directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", fmt.Errorf("secure endpoint token directory: %w", err)
	}

	path := filepath.Join(dir, name+".token")
	temporary, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temporary endpoint token: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("secure temporary endpoint token: %w", err)
	}
	if _, err := temporary.WriteString(token + "\n"); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("write endpoint token: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("sync endpoint token: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close endpoint token: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", fmt.Errorf("install endpoint token: %w", err)
	}
	return path, nil
}

// RotateEndpointToken atomically replaces a saved endpoint token and returns
// its plaintext value and path. Running publishers observe the file change and
// send only the new digest to the relay.
func RotateEndpointToken(tunnelID string) (token, path string, err error) {
	token, _, err = GenerateEndpointToken()
	if err != nil {
		return "", "", err
	}
	path, err = SaveEndpointToken(tunnelID, token)
	if err != nil {
		return "", "", err
	}
	return token, path, nil
}

// LoadEndpointToken reads a previously generated endpoint token.
func LoadEndpointToken(tunnelID string) (string, error) {
	name, err := safeEndpointName(tunnelID)
	if err != nil {
		return "", err
	}
	dir, err := endpointTokenDirectory()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name+".token")
	return loadEndpointTokenFile(path)
}

func endpointTokenDirectory() (string, error) {
	base := strings.TrimSpace(os.Getenv(configDirectoryEnvironment))
	if base != "" {
		if !filepath.IsAbs(base) {
			return "", fmt.Errorf("%s must be an absolute path", configDirectoryEnvironment)
		}
		return filepath.Join(filepath.Clean(base), "endpoints"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home directory: %w", err)
	}
	return filepath.Join(home, ".tunn", "endpoints"), nil
}

func loadEndpointTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read endpoint token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if !strings.HasPrefix(token, endpointTokenPrefix) {
		return "", fmt.Errorf("invalid endpoint token in %s", path)
	}
	return token, nil
}

func endpointTokenDigestFromFile(path string) ([]byte, error) {
	token, err := loadEndpointTokenFile(path)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(token))
	return digest[:], nil
}

func safeEndpointName(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) == 0 || len(value) > 63 {
		return "", fmt.Errorf("invalid endpoint name %q", value)
	}
	for index, char := range value {
		isAlphaNumeric := char >= 'a' && char <= 'z' || char >= '0' && char <= '9'
		if !isAlphaNumeric && (char != '-' || index == 0 || index == len(value)-1) {
			return "", fmt.Errorf("invalid endpoint name %q", value)
		}
	}
	return value, nil
}
