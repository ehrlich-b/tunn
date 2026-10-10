package client

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"time"
)

// LifecycleState is the publisher's connection state. Hooks run serially.
type LifecycleState string

const (
	StateConnecting   LifecycleState = "connecting"
	StateReady        LifecycleState = "ready"
	StateReconnecting LifecycleState = "reconnecting"
)

type LifecycleEvent struct {
	State      LifecycleState
	PublicURL  string
	RetryDelay time.Duration
	Err        error
}

type FailureKind string

const (
	FailureConnection   FailureKind = "connection"
	FailureRegistration FailureKind = "registration"
	FailureProtocol     FailureKind = "protocol"
)

// ClassifyFailure exposes a stable category without reflecting remote text.
func ClassifyFailure(err error) FailureKind {
	var permanent *permanentTunnelError
	if errors.As(err, &permanent) && permanent.kind != "" {
		return permanent.kind
	}
	return FailureConnection
}

func (s *ServeClient) lifecycle(event LifecycleEvent) {
	if s.OnLifecycle != nil {
		s.OnLifecycle(event)
	}
}

func (s *ServeClient) localDialContext() func(context.Context, string, string) (net.Conn, error) {
	if s.LocalDialContext != nil {
		return s.LocalDialContext
	}
	return s.DialContext
}

func (s *ServeClient) localTLSConfig() *tls.Config {
	if s.LocalTLSConfig != nil {
		return s.LocalTLSConfig.Clone()
	}
	return &tls.Config{InsecureSkipVerify: s.SkipLocalTLSVerify}
}

func (s *ServeClient) log(level slog.Level, message string, args ...any) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if s.SafeLogs {
		args = nil
	}
	logger.Log(context.Background(), level, message, args...)
}
