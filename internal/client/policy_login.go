package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const policyOwnerFilename = "policy-owner.json"

type policyOwnerCredentials struct {
	Server  string    `json:"server"`
	Access  string    `json:"access_token"`
	Expires time.Time `json:"expires_at"`
}

// LoginPolicyOwner uses the existing browser-authorized, 24-hour management
// exchange. It never converts a scoped device credential into an owner token.
func LoginPolicyOwner(ctx context.Context, server string, insecure bool, out io.Writer) error {
	origin, err := canonicalCredentialServer(server)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "Authorize account management in your browser. This separate credential lasts 24 hours and can administer your account. Publisher and CONNECT credentials remain unchanged.")
	l := &LoginClient{ServerAddr: strings.TrimPrefix(origin, "https://"), Insecure: insecure, Output: out, PolicyOwner: true}
	return l.Run(ctx)
}

func (l *LoginClient) savePolicyOwnerCredentials(token *TokenResponse) error {
	if token == nil || token.AccessToken == "" || token.RefreshToken != "" || token.ExpiresIn < 1 || token.ExpiresIn > 86400 {
		return fmt.Errorf("invalid management login response")
	}
	origin, err := canonicalCredentialServer(l.ServerAddr)
	if err != nil {
		return err
	}
	dir, err := configDirectory()
	if err != nil {
		return err
	}
	unlock, err := lockCredentials(context.Background(), dir)
	if err != nil {
		return err
	}
	defer unlock()
	data, err := json.Marshal(policyOwnerCredentials{Server: origin, Access: token.AccessToken, Expires: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)})
	if err != nil {
		return err
	}
	if len(data) > 16384 {
		return fmt.Errorf("management login response exceeds credential size limit")
	}
	_, err = writePrivateTokenFile(dir, policyOwnerFilename, string(data)+"\n")
	return err
}

// LoadPolicyOwnerToken cannot fall back to the scoped publisher token or send
// an account-management credential to an origin selected after login.
func LoadPolicyOwnerToken(server string) (string, error) {
	origin, err := canonicalCredentialServer(server)
	if err != nil {
		return "", err
	}
	dir, err := configDirectory()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, policyOwnerFilename)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return "", fmt.Errorf("owner sign-in required; run 'tunn policy login' for this relay or use --owner-token-file")
	}
	if err != nil {
		return "", fmt.Errorf("owner credential unavailable; run 'tunn policy login'")
	}
	if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
		return "", fmt.Errorf("owner credential must be a private regular file; run 'tunn policy login'")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("owner credential unavailable; run 'tunn policy login'")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", fmt.Errorf("owner credential changed; run 'tunn policy login'")
	}
	data, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(data) > 16384 {
		return "", fmt.Errorf("owner credential unavailable; run 'tunn policy login'")
	}
	var saved policyOwnerCredentials
	if json.Unmarshal(data, &saved) != nil || saved.Access == "" || !time.Now().Before(saved.Expires) {
		return "", fmt.Errorf("owner credential expired or invalid; run 'tunn policy login'")
	}
	if saved.Server != origin {
		return "", fmt.Errorf("owner login belongs to another relay; run 'tunn policy login' for this relay or choose its TUNN_CONFIG_DIR")
	}
	return saved.Access, nil
}
