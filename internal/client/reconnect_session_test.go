package client

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestReconnectSessionConflictClassification(t *testing.T) {
	for _, mode := range []string{"first-attempt-pending", "ordinary-conflict-after-success", "replacement-conflict-after-pending"} {
		t.Run(mode, func(t *testing.T) {
			backend := &sessionConflictRelay{t: t, mode: mode, registered: make(chan struct{})}
			g := grpc.NewServer()
			pb.RegisterTunnelServiceServer(g, backend)
			relay := httptest.NewUnstartedServer(g)
			relay.EnableHTTP2 = true
			relay.StartTLS()
			defer relay.Close()
			defer g.Stop()
			s := &ServeClient{TunnelID: "name", ServerAddr: strings.TrimPrefix(relay.URL, "https://"), Insecure: true, Quiet: true,
				InitialDelay: time.Millisecond, MaxReconnectDelay: time.Millisecond,
				OnRegistered:     func(string) { close(backend.registered) },
				Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
				publisherSession: "must-not-survive-a-new-run"}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := s.Run(ctx)
			want := int32(2)
			if mode == "first-attempt-pending" {
				want = 1
			}
			if mode == "replacement-conflict-after-pending" {
				want = 3
			}
			if err == nil || errors.Is(err, context.DeadlineExceeded) || backend.calls.Load() != want {
				t.Fatalf("conflict classification: calls=%d want=%d err=%v", backend.calls.Load(), want, err)
			}
		})
	}
}

type sessionConflictRelay struct {
	pb.UnimplementedTunnelServiceServer
	t          *testing.T
	mode       string
	calls      atomic.Int32
	registered chan struct{}
}

func (r *sessionConflictRelay) EstablishTunnel(stream pb.TunnelService_EstablishTunnelServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	call := r.calls.Add(1)
	previous := msg.GetRegisterClient().PreviousSession
	if call == 1 {
		if previous != "" {
			r.t.Errorf("new Run retained session %q", previous)
		}
		if r.mode != "first-attempt-pending" {
			if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://name.invalid", PublisherSession: "prior"}}}); err != nil {
				return err
			}
			select {
			case <-r.registered:
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
			return status.Error(codes.Unavailable, "synthetic disconnect")
		}
	} else if previous != "prior" {
		r.t.Errorf("reconnect lost successful session: %q", previous)
	}
	code := ""
	if r.mode == "first-attempt-pending" || r.mode == "replacement-conflict-after-pending" && call == 2 {
		code = common.PublisherSessionPending
	}
	return stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{ErrorMessage: "tunnel ID already in use", ErrorCode: code}}})
}
