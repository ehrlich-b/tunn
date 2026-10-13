package client

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/ehrlich-b/tunn/internal/common"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ehrlich-b/tunn/internal/webhook"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/protobuf/proto"
)

// LoadWebhookSecret reads a private regular file with a bounded size. Errors do
// not contain the path or contents. One terminal line ending is optional.
func LoadWebhookSecret(path string) ([]byte, error) {
	return loadWebhookSecretFile(path, true)
}

func loadWebhookSecretFile(path string, trimLineEnding bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("webhook secret requires a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open webhook secret file")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("webhook secret file must be private (chmod 600)")
	}
	data, err := io.ReadAll(io.LimitReader(file, webhook.MaxSecretSize+3))
	if err != nil {
		return nil, errors.New("cannot read webhook secret file")
	}
	value := string(data)
	if trimLineEnding {
		value = strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r")
	}
	if len(value) == 0 || len(value) > webhook.MaxSecretSize {
		return nil, errors.New("webhook secret must contain 1–4096 bytes")
	}
	return []byte(value), nil
}

// SaveWebhookSecret uses the same atomic private-directory/file storage as
// endpoint access tokens. The source key never appears in CLI arguments/logs.
func SaveWebhookSecret(server, endpoint, provider, account string, secret []byte) (string, error) {
	path, err := webhookSecretLocation(server, endpoint, provider, account)
	if err != nil {
		return "", errors.New("invalid webhook endpoint name")
	}
	if len(secret) == 0 || len(secret) > webhook.MaxSecretSize {
		return "", errors.New("invalid webhook secret length")
	}
	return writePrivateTokenFile(filepath.Dir(path), filepath.Base(path), string(secret))
}

func (s *ServeClient) registrationWebhookPolicy() (*pb.WebhookPolicy, error) {
	if s.WebhookPolicy == nil {
		if s.WebhookSecretPath != "" {
			return nil, errors.New("webhook secret file requires a webhook policy")
		}
		return nil, nil
	}
	if s.EndpointProtocol != "" && s.EndpointProtocol != "http" || s.registrationTarget() == "mcp" {
		return nil, errors.New("webhook policy requires HTTP")
	}
	policy := proto.Clone(s.WebhookPolicy).(*pb.WebhookPolicy)
	if s.WebhookSecretPath != "" {
		expected, err := webhookSecretLocation(s.ServerAddr, s.TunnelID, policy.Provider, WebhookAccountBinding(s.AuthToken))
		if err != nil || filepath.Clean(s.WebhookSecretPath) != expected {
			return nil, errors.New("webhook secret does not match this publication")
		}
		// Stored keys have already had their input line ending removed. Reload
		// their exact bytes so trailing whitespace cannot change on reconnect.
		secret, err := loadWebhookSecretFile(s.WebhookSecretPath, false)
		if err != nil {
			return nil, err
		}
		policy.Secret = secret
	}
	if _, err := webhook.Compile(policy); err != nil {
		return nil, err
	}
	return policy, nil
}

// WebhookAccountBinding remains stable across renewable account tokens.
func WebhookAccountBinding(token string) string {
	if email, err := common.ExtractEmailFromJWT(token); err == nil && email != "" {
		return common.NormalizeEmail(email)
	}
	digest := sha256.Sum256([]byte(token))
	return "credential:" + hex.EncodeToString(digest[:])
}
func webhookSecretLocation(server, endpoint, provider, account string) (string, error) {
	if _, err := safeEndpointName(endpoint); err != nil {
		return "", err
	}
	origin, err := canonicalCredentialServer(server)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(origin)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := u.Port()
	if port == "" || port == "443" {
		u.Host = host
		if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		}
	} else {
		u.Host = net.JoinHostPort(host, port)
	}
	if provider == "" || account == "" {
		return "", errors.New("webhook publication binding required")
	}
	digest := sha256.Sum256([]byte(u.String() + "\x00" + endpoint + "\x00" + provider + "\x00" + account))
	dir, err := endpointTokenDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "webhooks", hex.EncodeToString(digest[:])+".secret"), nil
}
