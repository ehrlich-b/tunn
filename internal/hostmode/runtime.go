package hostmode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/mcpbridge"
)

func Credentials(c *Config) (string, error) {
	var token string
	if c.TokenFile != "" {
		b, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return "", fmt.Errorf("read host token: %w", err)
		}
		token = string(b)
	} else {
		var err error
		token, err = client.LoadToken()
		if err != nil {
			return "", err
		}
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("empty or invalid host credential")
	}
	return token, nil
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
					common.LogError("host endpoint stopped; retrying", "name", t.Name)
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
	token, err := client.LoadEndpointToken(name)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		token, _, err = client.GenerateEndpointToken()
		if err != nil {
			return "", err
		}
		return client.SaveEndpointToken(name, token)
	}
	// Existing tokens survive restarts. Compute their path without rewriting
	// the file, so live rotation cannot race a daemon's redundant save.
	base := strings.TrimSpace(os.Getenv("TUNN_CONFIG_DIR"))
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".tunn")
	}
	return filepath.Join(base, "endpoints", name+".token"), nil
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
	s.EndpointTokenPath, err = endpointToken(t.Name)
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
