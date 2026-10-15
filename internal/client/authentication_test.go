package client

import (
	"context"
	"errors"
	"fmt"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthenticationFailureSeparatesAdmissionAndProtocol(t *testing.T) {
	for _, test := range []struct {
		err  error
		want bool
	}{
		{status.Error(codes.Unauthenticated, "expired"), true},
		{&permanentTunnelError{kind: FailureRegistration, err: errors.New("registration failed: Invalid or expired token. Run 'tunn login' to refresh.")}, true},
		{&permanentTunnelError{kind: FailureRegistration, err: errors.New("tunnel limit reached (3/3)")}, false},
		{status.Error(codes.ResourceExhausted, "monthly quota"), false},
		{&permanentTunnelError{kind: FailureProtocol, err: errors.New("authentication required")}, false},
	} {
		if got := AuthenticationFailure(test.err); got != test.want {
			t.Fatalf("%v: %v", test.err, got)
		}
	}
}

// Authentication rejection is terminal for static logins; admission rejection
// must not rotate a renewable credential or retry a failed publish operation.
func TestCLIRejectionsStopWithoutRetry(t *testing.T) {
	for _, renewable := range []bool{false, true} {
		t.Run(fmt.Sprint(renewable), func(t *testing.T) {
			var calls atomic.Int32
			g := grpc.NewServer()
			pb.RegisterTunnelServiceServer(g, &cliRejectionRelay{calls: &calls, quota: renewable})
			relay := httptest.NewUnstartedServer(g)
			relay.EnableHTTP2 = true
			relay.StartTLS()
			defer relay.Close()
			defer g.Stop()
			s := &ServeClient{ServerAddr: strings.TrimPrefix(relay.URL, "https://"), Insecure: true, Quiet: true, AuthToken: "synthetic", InitialDelay: time.Millisecond, MaxReconnectDelay: time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			if renewable {
				manager, state := credentialFixture(t)
				state.Expires = time.Now().Add(time.Hour)
				if err := saveCredentialState(manager.path, state); err != nil {
					t.Fatal(err)
				}
				manager.HTTPClient = &http.Client{Transport: loginRoundTripper(func(*http.Request) (*http.Response, error) {
					t.Error("quota refreshed login")
					return nil, errors.New("unexpected refresh")
				})}
				s.Credentials = manager
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := s.Run(ctx)
			if err == nil || errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
				t.Fatal("rejection retried", err, calls.Load())
			}
		})
	}
}

type cliRejectionRelay struct {
	pb.UnimplementedTunnelServiceServer
	calls *atomic.Int32
	quota bool
}

func (r *cliRejectionRelay) EstablishTunnel(s pb.TunnelService_EstablishTunnelServer) error {
	r.calls.Add(1)
	if _, err := s.Recv(); err != nil {
		return err
	}
	if r.quota {
		return s.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: false, ErrorMessage: "tunnel limit reached (3/3)"}}})
	}
	return status.Error(codes.Unauthenticated, "expired")
}

func TestCLICredentialRenewalPreservesTemporaryFailure(t *testing.T) {
	manager, state := credentialFixture(t)
	state.Expires = time.Now().Add(-time.Minute)
	if err := saveCredentialState(manager.path, state); err != nil {
		t.Fatal(err)
	}
	manager.HTTPClient = &http.Client{Transport: loginRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("private transport response"))}, nil
	})}
	_, err := manager.Token(context.Background(), false)
	if err == nil || !RetryableCredentialError(err) || AuthenticationFailure(err) || strings.Contains(err.Error(), "private transport response") {
		t.Fatal("temporary renewal was treated as lost login", err)
	}
}

func TestCLIQuotaStatusStopsWithoutRetry(t *testing.T) {
	var calls atomic.Int32
	g := grpc.NewServer()
	pb.RegisterTunnelServiceServer(g, &cliQuotaStatusRelay{calls: &calls})
	relay := httptest.NewUnstartedServer(g)
	relay.EnableHTTP2 = true
	relay.StartTLS()
	defer relay.Close()
	defer g.Stop()
	s := &ServeClient{ServerAddr: strings.TrimPrefix(relay.URL, "https://"), Insecure: true, Quiet: true, AuthToken: "synthetic", InitialDelay: time.Millisecond, MaxReconnectDelay: time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := s.Run(ctx)
	if status.Code(err) != codes.ResourceExhausted || calls.Load() != 1 {
		t.Fatal("resource limit retried", err, calls.Load())
	}
}

type cliQuotaStatusRelay struct {
	pb.UnimplementedTunnelServiceServer
	calls *atomic.Int32
}

func (r *cliQuotaStatusRelay) EstablishTunnel(s pb.TunnelService_EstablishTunnelServer) error {
	r.calls.Add(1)
	if _, err := s.Recv(); err != nil {
		return err
	}
	return status.Error(codes.ResourceExhausted, "limit reached")
}
