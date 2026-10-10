package metering

import (
	"context"
	"errors"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Remote follows the relay's existing login-node discovery. There is no local
// fail-open cache: ambiguous admissions/charges cannot be retried as new usage.
type Remote struct{ Connection func() *grpc.ClientConn }

func (r *Remote) client() (pb.MeteringClient, error) {
	conn := r.Connection()
	if conn == nil {
		return nil, errors.New("metering authority unavailable")
	}
	return pb.NewMeteringClient(conn), nil
}
func rpcContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}
func (r *Remote) Resolve(ctx context.Context, in *pb.ResolveRequest) (*pb.Grant, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := rpcContext(ctx)
	defer cancel()
	return c.Resolve(ctx, in)
}
func (r *Remote) CreateGrant(ctx context.Context, in *pb.Grant) (*pb.Grant, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := rpcContext(ctx)
	defer cancel()
	return c.CreateGrant(ctx, in)
}
func (r *Remote) RevokeGrant(ctx context.Context, in *pb.Grant) (*emptypb.Empty, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := rpcContext(ctx)
	defer cancel()
	return c.RevokeGrant(ctx, in)
}
func (r *Remote) ListGrants(ctx context.Context, in *pb.ListGrantsRequest) (*pb.ListGrantsResponse, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := rpcContext(ctx)
	defer cancel()
	return c.ListGrants(ctx, in)
}
func (r *Remote) Admit(ctx context.Context, in *pb.Event) (*pb.Decision, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := rpcContext(ctx)
	defer cancel()
	return c.Admit(ctx, in)
}
func (r *Remote) Charge(ctx context.Context, in *pb.ChargeRequest) (*pb.Decision, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := rpcContext(ctx)
	defer cancel()
	return c.Charge(ctx, in)
}
func (r *Remote) Finish(ctx context.Context, in *pb.Event) (*emptypb.Empty, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := rpcContext(ctx)
	defer cancel()
	return c.Finish(ctx, in)
}
func (r *Remote) Export(ctx context.Context, in *pb.ExportRequest) (*pb.ExportResponse, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := rpcContext(ctx)
	defer cancel()
	return c.Export(ctx, in, grpc.MaxCallRecvMsgSize(128<<20))
}
