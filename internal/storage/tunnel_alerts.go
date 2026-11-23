package storage

import (
	"context"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
)

// TunnelAlerts is optional so embedded storage implementations remain compatible.
type TunnelAlerts interface {
	TunnelAlert(context.Context, *pb.TunnelAlertRequest) (*pb.TunnelAlertResponse, error)
}

func (s *ProxyStorage) TunnelAlert(ctx context.Context, r *pb.TunnelAlertRequest) (*pb.TunnelAlertResponse, error) {
	c := s.getClient()
	if c == nil {
		return nil, ErrNotAvailable
	}
	return c.TunnelAlert(ctx, r)
}

func (s *LocalStorage) TunnelAlert(ctx context.Context, r *pb.TunnelAlertRequest) (*pb.TunnelAlertResponse, error) {
	alerts := store.NewTunnelAlertStore(s.db)
	if r.Operation == "settings" || r.Operation == "save_settings" {
		var update *store.TunnelAlertSettings
		if r.Operation == "save_settings" {
			update = &store.TunnelAlertSettings{Enabled: r.Enabled, ThresholdSeconds: r.ThresholdSeconds, OnGracefulStop: r.OnGracefulStop}
		}
		settings, err := alerts.Settings(ctx, r.AccountId, update)
		if err != nil {
			return nil, err
		}
		return &pb.TunnelAlertResponse{Enabled: settings.Enabled, ThresholdSeconds: settings.ThresholdSeconds, OnGracefulStop: settings.OnGracefulStop}, nil
	}
	account, err := s.accounts.GetByIDContext(ctx, r.AccountId)
	if err != nil {
		return nil, err
	}
	owner := account.ID
	s.activeTunnelsMu.Lock()
	defer s.activeTunnelsMu.Unlock()
	generation := s.activeSessions[r.Tunnel]
	switch r.Operation {
	case "up", "heartbeat", "down", "graceful":
		// Keep the last versioned generation after release so a delayed heartbeat
		// cannot recreate its claim. A subsequent admission replaces this fence.
		if generation != "" {
			if generation != r.Session || s.activeTunnels[r.Tunnel] == "" && (r.Operation == "up" || r.Operation == "heartbeat") {
				return &pb.TunnelAlertResponse{}, nil
			}
			if id := s.activeTunnels[r.Tunnel]; id != "" {
				active, err := s.accounts.GetByIDContext(ctx, id)
				if err != nil || active.ID != owner {
					return nil, fmt.Errorf("publisher owner does not match registration")
				}
			}
		}
	}
	if r.Operation == "up" {
		active, err := s.accounts.GetByIDContext(ctx, s.activeTunnels[r.Tunnel])
		if err != nil || active.ID != owner {
			return nil, fmt.Errorf("publisher is not registered")
		}
		store.RecordFunnel(ctx, s.db, "tunnel", owner)
	}
	session, err := alerts.Session(ctx, r.Tunnel)
	if err != nil {
		return nil, err
	}
	err = alerts.Report(ctx, owner, r.Tunnel, r.Session, r.Operation, r.LastError, s.currentTime())
	if err == nil {
		// Versioned admission is released only by UnregisterTunnelSession after
		// the relay confirms route removal. Reports describe availability only.
		if generation == "" && (r.Operation == "down" || r.Operation == "graceful") && (session == "" || session == r.Session) {
			delete(s.activeTunnels, r.Tunnel)
		}
		if generation == "" && r.Operation == "heartbeat" && session != "" && session == r.Session {
			s.activeTunnels[r.Tunnel] = owner
		}
	}
	return &pb.TunnelAlertResponse{}, err
}

func (s *LocalStorage) ClaimTunnelAlerts(ctx context.Context) ([]store.TunnelAlert, error) {
	s.activeTunnelsMu.Lock()
	defer s.activeTunnelsMu.Unlock()
	alerts := store.NewTunnelAlertStore(s.db)
	expired, err := alerts.Expire(ctx, s.currentTime())
	if err != nil {
		return nil, err
	}
	for _, tunnel := range expired {
		// The heartbeat lease is an availability signal, not proof that a
		// relay removed its route. Keep versioned admission until release.
		if s.activeSessions[tunnel] == "" {
			delete(s.activeTunnels, tunnel)
		}
	}
	return alerts.Claim(ctx, s.currentTime())
}

func (s *LocalStorage) DeliveredTunnelAlert(ctx context.Context, a store.TunnelAlert) error {
	return store.NewTunnelAlertStore(s.db).Delivered(ctx, a)
}
