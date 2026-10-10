package hostmode

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/mcpbridge"
	"github.com/golang-jwt/jwt/v4"
)

func Credentials(c *Config) (string, error) {
	path := c.TokenFile
	if path == "" {
		base, err := credentialsDirectory(c)
		if err != nil {
			return "", err
		}
		path = filepath.Join(base, "token")
	}
	b, err := readPrivateFile(path)
	if err != nil {
		return "", fmt.Errorf("read host token (run tunn login or check token_file): %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("empty or invalid host credential")
	}
	// This is a local expiry diagnostic, not signature authentication. Static
	// self-hosted tokens remain supported; the relay verifies their identity.
	if strings.HasPrefix(token, "eyJ") {
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil || !claims.VerifyExpiresAt(time.Now().Unix(), true) {
			return "", fmt.Errorf("login expired or invalid; log in to the same relay/account and restart the service")
		}
	}
	return token, nil
}

func credentialsDirectory(c *Config) (string, error) {
	base := c.CredentialsDir
	if base == "" {
		base = strings.TrimSpace(os.Getenv("TUNN_CONFIG_DIR"))
	}
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".tunn")
	}
	if !filepath.IsAbs(base) {
		return "", fmt.Errorf("credentials_dir and TUNN_CONFIG_DIR must be absolute")
	}
	return base, nil
}

type Health struct {
	mu      sync.Mutex
	Machine string         `json:"machine"`
	Ready   bool           `json:"ready"`
	Tunnels []TunnelHealth `json:"tunnels"`
}

type TunnelHealth struct {
	Name   string `json:"name"`
	Online bool   `json:"online"`
}

func NewHealth(c *Config) *Health {
	h := &Health{Machine: c.Machine, Tunnels: []TunnelHealth{}}
	for _, t := range c.Tunnels {
		h.Tunnels = append(h.Tunnels, TunnelHealth{Name: t.Name})
	}
	return h
}

func (h *Health) Set(name string, online bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Ready = true
	for i := range h.Tunnels {
		if h.Tunnels[i].Name == name {
			h.Tunnels[i].Online = online
		}
		h.Ready = h.Ready && h.Tunnels[i].Online
	}
}

func (h *Health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/health" && r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
		http.NotFound(w, r)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !h.Ready && r.URL.Path != "/healthz" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(h)
}

// Runtime binds health before reserving names so a second daemon on the same
// machine cannot replace its credentials or start competing MCP children.
type Runtime struct {
	Config    *Config
	API       API
	TunnelKey string
	Stderr    io.Writer // Stdio child stderr is discarded by default (may hold secrets).
	OnListen  func(string)
}

func waitReconnect(ctx context.Context, attempt int) error {
	timer := time.NewTimer(client.ReconnectDelay(time.Second, 30*time.Second, attempt))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (r *Runtime) Run(ctx context.Context) error {
	if err := r.Config.Validate(); err != nil {
		return err
	}
	if err := ValidateAddress(r.API.Server); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", r.Config.Health)
	if err != nil {
		return fmt.Errorf("bind loopback health: %w", err)
	}
	h := NewHealth(r.Config)
	healthServer := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	healthDone := make(chan error, 1)
	go func() {
		err := healthServer.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			cancel()
		}
		healthDone <- err
	}()
	defer func() { _ = healthServer.Close(); <-healthDone }()
	if r.OnListen != nil {
		r.OnListen(listener.Addr().String())
	}
	for attempt := 0; ; attempt++ {
		err := r.API.Register(ctx, r.Config)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var failure *APIError
		if errors.As(err, &failure) && failure.Permanent() {
			return err
		}
		common.LogError("host registry unavailable; retrying")
		if err := waitReconnect(ctx, attempt); err != nil {
			return err
		}
	}
	var wg sync.WaitGroup
	for _, tunnel := range r.Config.Tunnels {
		wg.Add(1)
		go func(t Tunnel) {
			defer wg.Done()
			for attempt := 0; ctx.Err() == nil; attempt++ {
				if err := r.publish(ctx, t, h); err != nil && ctx.Err() == nil {
					common.LogError("host endpoint stopped; retrying", "name", t.Name, "error", err)
				}
				if ctx.Err() != nil || waitReconnect(ctx, attempt) != nil {
					return
				}
			}
		}(tunnel)
	}
	<-ctx.Done()
	wg.Wait()
	return ctx.Err()
}

func endpointToken(name string) (string, error) {
	base, err := credentialsDirectory(&Config{})
	if err != nil {
		return "", err
	}
	return endpointTokenIn(base, name)
}

func endpointTokenIn(base, name string) (string, error) {
	if !filepath.IsAbs(base) || !ValidName(name) {
		return "", fmt.Errorf("endpoint credential requires an absolute root and a valid name")
	}
	dir := filepath.Join(base, "endpoints")
	for _, path := range []string{base, dir} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return "", err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0) {
			return "", fmt.Errorf("endpoint credentials require non-symlink directories without group/world write access (Windows requires a private user ACL)")
		}
	}
	path := filepath.Join(dir, name+".token")
	data, err := readPrivateFile(path)
	if os.IsNotExist(err) {
		token, _, err := client.GenerateEndpointToken()
		if err != nil {
			return "", err
		}
		if err := createPrivateFile(path, []byte(token+"\n")); err != nil && !os.IsExist(err) {
			return "", err
		}
		// A competing first start may have won publication; load its credential.
		data, err = readPrivateFile(path)
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	random, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "tunn_ep_"))
	if !strings.HasPrefix(token, "tunn_ep_") || err != nil || len(random) != 32 {
		return "", fmt.Errorf("invalid endpoint credential; existing file retained: %s", path)
	}
	return path, nil
}

func (r *Runtime) publish(ctx context.Context, t Tunnel, health *Health) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := &client.ServeClient{TunnelID: t.Name, HostID: r.Config.Machine, ServerAddr: r.API.Server,
		AuthToken: r.API.Token, TunnelKey: r.TunnelKey, Insecure: r.API.Insecure, Quiet: true, Persistent: true,
		AllowedEmails: append([]string(nil), t.Allow...), OnState: func(online bool) { health.Set(t.Name, online) }}
	defer health.Set(t.Name, false)
	if len(s.AllowedEmails) == 0 {
		owner, err := common.ExtractEmailFromJWT(r.API.Token)
		if err != nil {
			owner = "client@local"
		}
		s.AllowedEmails = []string{owner}
	}
	var err error
	base, err := credentialsDirectory(r.Config)
	if err != nil {
		return err
	}
	s.EndpointTokenPath, err = endpointTokenIn(base, t.Name)
	if err != nil {
		return err
	}
	if t.Kind == "tcp" || (t.Kind == "unix" && t.As != "http") {
		s.EndpointProtocol, s.TargetURL = "tcp", t.Target
		if t.Kind == "unix" {
			s.TargetNetwork = "unix"
		}
	} else if t.Kind == "unix" {
		s.TargetURL, s.TargetNetwork, s.DialAddress = "http://localhost", "unix", t.Target
	} else if len(t.Command) > 0 {
		stderr := r.Stderr
		if stderr == nil {
			stderr = io.Discard
		}
		bridge, err := mcpbridge.StartWithOptions(ctx, t.Command, stderr, mcpbridge.Options{AllowedTools: t.Tools})
		if err != nil {
			return err
		}
		defer func() {
			shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = bridge.Close(shutdown)
		}()
		go func() {
			select {
			case <-ctx.Done():
			case <-bridge.Done():
				cancel()
			}
		}()
		s.TargetURL, s.PublicPath = bridge.URL(), "/mcp"
	} else {
		u, err := HTTPURL(t.Target)
		if err != nil {
			return err
		}
		s.TargetURL = u.Scheme + "://" + u.Host
		if t.Kind == "mcp" {
			s.PublicPath, s.UpstreamPath, s.UpstreamRawQuery = "/mcp", u.EscapedPath(), u.RawQuery
			if s.UpstreamPath == "" {
				s.UpstreamPath = "/mcp"
			}
		}
	}
	return s.Run(ctx)
}
