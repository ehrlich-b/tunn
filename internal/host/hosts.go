package host

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/hostmode"
	"github.com/ehrlich-b/tunn/internal/store"
)

func (s *TunnelServer) EnableHostMode(db *sql.DB) error {
	if !s.cfg.HostModeEnabled {
		return fmt.Errorf("host mode is disabled")
	}
	if !s.cfg.LoginNode || s.cfg.PublicMode || s.cfg.NodeAddresses != "" || s.cfg.FlyAppName != "" {
		return fmt.Errorf("host mode requires one authenticated, standalone login relay")
	}
	if s.accounts == nil {
		return fmt.Errorf("host mode requires account storage")
	}
	registry, err := store.NewHostStore(db)
	if err != nil {
		return err
	}
	s.hosts = registry
	return nil
}

func (s *TunnelServer) hostAccount(token string, create bool) (*store.Account, error) {
	if token == "" {
		return nil, fmt.Errorf("authentication required")
	}
	var email string
	if s.cfg.ClientSecret != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.ClientSecret)) == 1 {
		email = "client@local"
	} else if userEmail := s.validateUserToken(token); userEmail != "" {
		email = userEmail
	} else {
		var err error
		email, err = s.validateJWTAndExtractEmail(token)
		if err != nil {
			return nil, fmt.Errorf("invalid or expired login token")
		}
	}
	a, err := s.accounts.GetByEmail(email)
	if err == sql.ErrNoRows {
		if !create {
			return nil, nil
		}
		return s.accounts.FindOrCreateByEmails([]string{email}, "host")
	}
	return a, err
}

func (s *TunnelServer) HandleHosts(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.HostModeEnabled || s.hosts == nil {
		http.Error(w, "host mode is disabled on this relay", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	a, err := s.hostAccount(token, r.Method == http.MethodPost)
	if err != nil {
		http.Error(w, "invalid or expired login token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		machines := []common.Machine{}
		if a != nil {
			machines, err = s.hosts.List(a.ID)
			if err != nil {
				http.Error(w, "could not list hosts", http.StatusServiceUnavailable)
				return
			}
			s.mu.RLock()
			for i := range machines {
				m := &machines[i]
				for j := range m.Tunnels {
					e := &m.Tunnels[j]
					e.URL = "https://" + e.Name + "." + s.cfg.Domain
					if e.Kind == "mcp" {
						e.URL += "/mcp"
					}
					if conn := s.tunnels[e.Name]; conn != nil && conn.AccountID == a.ID && conn.HostID == m.Name {
						e.Online = true
						m.Online = true
					}
				}
			}
			s.mu.RUnlock()
		}
		_ = json.NewEncoder(w).Encode(machines)
		return
	}
	var manifest common.HostManifest
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&manifest); err != nil {
		http.Error(w, "invalid host manifest", http.StatusBadRequest)
		return
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		http.Error(w, "expected one manifest", http.StatusBadRequest)
		return
	}
	if !hostmode.ValidName(manifest.Machine) || len(manifest.Tunnels) == 0 || len(manifest.Tunnels) > 10 {
		http.Error(w, "invalid machine or tunnel count", http.StatusBadRequest)
		return
	}
	names := map[string]bool{}
	for _, e := range manifest.Tunnels {
		if !isValidDNSLabel(e.Name) || isReservedSubdomain(e.Name) || names[e.Name] || (e.Kind != "http" && e.Kind != "mcp" && e.Kind != "tcp" && e.Kind != "unix") {
			http.Error(w, "invalid or duplicate endpoint", http.StatusBadRequest)
			return
		}
		names[e.Name] = true
	}
	// Serialize with stream admission so reservation cannot steal an actively
	// published name from another account, even if that name was ephemeral.
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range manifest.Tunnels {
		if conn := s.tunnels[e.Name]; conn != nil && conn.AccountID != a.ID {
			http.Error(w, "name is currently in use", http.StatusConflict)
			return
		}
	}
	if err := s.hosts.Register(a.ID, manifest); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"reserved": true})
}

func (s *TunnelServer) hostSeen(conn *TunnelConnection) {
	if conn.HostID != "" && s.hosts != nil {
		if err := s.hosts.Seen(conn.AccountID, conn.HostID, conn.TunnelID, time.Now()); err != nil {
			common.LogError("could not update host presence", "tunnel_id", conn.TunnelID)
		}
	}
}
