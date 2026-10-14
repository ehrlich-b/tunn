package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const credentialsFilename = "credentials.json"
const deviceReauthCapability = "device-reauth-v1"

type savedCredentials struct {
	Server  string    `json:"server"`
	Access  string    `json:"access_token"`
	Refresh string    `json:"refresh_token"`
	Device  string    `json:"device_id"`
	Expires time.Time `json:"expires_at"`
	Pending string    `json:"pending_request_id,omitempty"`
}

// CredentialManager coordinates renewal across all processes sharing a config
// directory. It never reads endpoint tokens or changes explicitly supplied secrets.
type CredentialManager struct {
	ServerAddr string
	HTTPClient *http.Client
	Now        func() time.Time // Optional clock for expiry decisions; nil uses time.Now
	path       string
	mu         sync.Mutex
	last       string
}

// Renewal starts a minute before expiry, so one attempt and its retry fit
// inside that margin and a lost response does not cost the relay lease.
const refreshRequestTimeout = 15 * time.Second

type credentialRefreshError struct {
	terminal bool
	message  string
}

func (e *credentialRefreshError) Error() string { return e.message }
func terminalCredentialError(err error) bool {
	var e *credentialRefreshError
	return errors.As(err, &e) && e.terminal
}

// ExitLoginRequired is the exit status of a publisher whose login can no
// longer renew. Service units set RestartPreventExitStatus to it so a revoked
// login stops once instead of restarting in a loop.
const ExitLoginRequired = 78

// LoginRequired reports whether only a new tunn login can recover from err:
// the relay terminally rejected renewal, or rejected a login that cannot renew.
func LoginRequired(err error) bool {
	if terminalCredentialError(err) || errors.Is(err, ErrNotLoggedIn) {
		return true
	}
	var permanent *permanentTunnelError
	return errors.As(err, &permanent) && permanent.kind == FailureRegistration && strings.Contains(permanent.Error(), "tunn login")
}

// LoginRequiredMessage is the single line a service logs before exiting with
// ExitLoginRequired.
func LoginRequiredMessage() string {
	dir, err := configDirectory()
	if err != nil {
		return "tunn: this machine's login is missing, expired or revoked and cannot renew; run 'tunn login' here, then restart this service"
	}
	return fmt.Sprintf("tunn: this machine's login is missing, expired or revoked and cannot renew; run 'TUNN_CONFIG_DIR=%s tunn login' here, then restart this service", dir)
}

func canonicalCredentialServer(server string) (string, error) {
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("credential server must be an HTTPS origin")
	}
	return "https://" + strings.ToLower(u.Host), nil
}

func (l *LoginClient) saveCredentials(token *TokenResponse) error {
	if l.PolicyOwner {
		return l.savePolicyOwnerCredentials(token)
	}
	if token.RefreshToken == "" {
		dir, err := configDirectory()
		if err != nil {
			return err
		}
		unlock, err := lockCredentials(context.Background(), dir)
		if err != nil {
			return err
		}
		defer unlock()
		if err = l.saveToken(token.AccessToken); err != nil {
			return err
		}
		if err = os.Remove(filepath.Join(dir, credentialsFilename)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	server, err := canonicalCredentialServer(l.ServerAddr)
	if err != nil {
		return err
	}
	if token.DeviceID == "" || token.ExpiresIn <= 60 {
		return fmt.Errorf("invalid durable login response")
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
	state := savedCredentials{Server: server, Access: token.AccessToken, Refresh: token.RefreshToken, Device: token.DeviceID, Expires: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)}
	if err = saveCredentialState(filepath.Join(dir, credentialsFilename), &state); err != nil {
		return err
	}
	return l.saveToken(token.AccessToken)
}

func saveCredentialState(path string, state *savedCredentials) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = writePrivateTokenFile(filepath.Dir(path), filepath.Base(path), string(data)+"\n")
	if err != nil {
		return err
	}
	return syncCredentialDirectory(filepath.Dir(path))
}
func readCredentialState(path string) (*savedCredentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state savedCredentials
	if err = json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("invalid saved credentials; run tunn login")
	}
	if state.Server == "" || state.Access == "" || state.Refresh == "" || state.Device == "" || state.Expires.IsZero() {
		return nil, fmt.Errorf("incomplete saved credentials; run tunn login")
	}
	return &state, nil
}

// LoadTunnelToken preserves legacy logins and selects renewable device state
// only for its original server. Errors never fall back to expired credentials.
func LoadTunnelToken(ctx context.Context, server string, insecure bool) (string, *CredentialManager, error) {
	dir, err := configDirectory()
	if err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, credentialsFilename)
	state, err := readCredentialState(path)
	if os.IsNotExist(err) {
		token, err := LoadToken()
		return token, nil, err
	}
	if err != nil {
		return "", nil, err
	}
	origin, err := canonicalCredentialServer(server)
	if err != nil {
		return "", nil, err
	}
	if origin != state.Server {
		return "", nil, fmt.Errorf("saved login belongs to a different server; choose its TUNN_CONFIG_DIR or run tunn login")
	}
	manager := &CredentialManager{ServerAddr: origin, path: path, HTTPClient: (&LoginClient{Insecure: insecure}).httpClient()}
	token, err := manager.Token(ctx, false)
	return token, manager, err
}
func (m *CredentialManager) currentTime() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Token refreshes before expiry or once after authentication rejection. A
// forced retry observes another process's refresh without rotating it again.
func (m *CredentialManager) Token(ctx context.Context, force bool) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := lockCredentials(ctx, filepath.Dir(m.path))
	if err != nil {
		return "", err
	}
	defer unlock()
	state, err := readCredentialState(m.path)
	if err != nil {
		return "", err
	}
	server, err := canonicalCredentialServer(m.ServerAddr)
	if err != nil {
		return "", err
	}
	if state.Server != server {
		return "", &credentialRefreshError{true, "credential server changed; run tunn login using the correct TUNN_CONFIG_DIR"}
	}
	mustRefresh := !m.currentTime().Before(state.Expires.Add(-time.Minute)) || state.Pending != "" || force && (m.last == "" || state.Access == m.last)
	if !mustRefresh {
		m.last = state.Access
		return state.Access, nil
	}
	if state.Pending == "" {
		var random [32]byte
		if _, err = rand.Read(random[:]); err != nil {
			return "", err
		}
		state.Pending = base64.RawURLEncoding.EncodeToString(random[:])
		if err = saveCredentialState(m.path, state); err != nil {
			return "", fmt.Errorf("persist refresh request: %w", err)
		}
	}
	data, _ := json.Marshal(map[string]string{"refresh_token": state.Refresh, "request_id": state.Pending})
	ctx, cancel := context.WithTimeout(ctx, refreshRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/device/refresh", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := m.HTTPClient
	if client == nil {
		client = (&LoginClient{}).httpClient()
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	started := m.currentTime()
	resp, err := copyClient.Do(req)
	if err != nil {
		return "", &credentialRefreshError{false, "credential refresh could not reach the login server; check network access and retry"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		terminal := resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429
		message := "credential refresh unavailable; check the login server and retry"
		if terminal {
			message = "device login revoked, reused or rejected; run tunn login on this device"
		}
		return "", &credentialRefreshError{terminal, message}
	}
	var token TokenResponse
	if err = json.NewDecoder(resp.Body).Decode(&token); err != nil || token.AccessToken == "" || token.RefreshToken == "" || token.DeviceID != state.Device || token.ExpiresIn <= 60 {
		return "", &credentialRefreshError{false, "invalid refresh response; check the login server and retry"}
	}
	state.Access = token.AccessToken
	state.Refresh = token.RefreshToken
	state.Expires = started.Add(time.Duration(token.ExpiresIn) * time.Second)
	state.Pending = ""
	if err = saveCredentialState(m.path, state); err != nil {
		return "", fmt.Errorf("save refreshed credentials: %w", err)
	}
	// The JSON state is authoritative; failure of the legacy mirror is visible.
	if _, err = writePrivateTokenFile(filepath.Dir(m.path), "token", state.Access); err != nil {
		return "", fmt.Errorf("save refreshed token mirror: %w", err)
	}
	m.last = state.Access
	return state.Access, nil
}

func prepareCredentialDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("credential directory must be a real private directory")
	}
	return os.Chmod(dir, 0700)
}
