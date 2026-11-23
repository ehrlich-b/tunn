package host

import (
	"context"
	"fmt"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
)

// A release obligation proves this relay removed (or never installed) this
// exact admission session. Names or authenticated ownership alone are not proof.
type registrationRelease struct{ tunnel, session string }

func (s *TunnelServer) rememberRegistrationReleaseLocked(release registrationRelease) {
	if s.pendingReleases == nil {
		s.pendingReleases = make(map[registrationRelease]struct{})
	}
	s.pendingReleases[release] = struct{}{}
}

func (s *TunnelServer) releaseRegistration(ctx context.Context, backend storage.TunnelSessions, release registrationRelease) error {
	s.mu.Lock()
	if conn := s.tunnels[release.tunnel]; conn != nil && conn.alertSession == release.session {
		s.mu.Unlock()
		return fmt.Errorf("publisher route is still installed")
	}
	s.rememberRegistrationReleaseLocked(release)
	s.mu.Unlock()
	if err := backend.UnregisterTunnelSession(ctx, release.tunnel, release.session); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.pendingReleases, release)
	s.mu.Unlock()
	return nil
}

// Admission also drains obligations for its name so recovery need not wait for
// the maintenance tick. Concurrent drains are safe: session release is idempotent
// and cannot clear a replacement, even if its RPC response is delayed.
func (s *TunnelServer) releasePendingRegistrations(ctx context.Context, tunnel string) error {
	backend, ok := s.storage.(storage.TunnelSessions)
	if !ok {
		return nil
	}
	s.mu.RLock()
	pending := make([]registrationRelease, 0, len(s.pendingReleases))
	for release := range s.pendingReleases {
		if tunnel == "" || release.tunnel == tunnel {
			pending = append(pending, release)
		}
	}
	s.mu.RUnlock()
	var firstErr error
	for _, release := range pending {
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := s.releaseRegistration(attempt, backend, release)
		cancel()
		if err != nil {
			common.LogError("pending publisher session release failed", "tunnel_id", release.tunnel, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Use the proxy lifetime, independently of a disconnected publisher or another
// registration. Only a confirmed conditional release removes an obligation.
func (s *TunnelServer) registrationReleaseLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.releasePendingRegistrations(ctx, "")
		}
	}
}
