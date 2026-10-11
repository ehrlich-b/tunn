package domains

import (
	"context"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Remote struct{ Connection func() *grpc.ClientConn }

func (r *Remote) client() (pb.DomainsClient, error) {
	conn := r.Connection()
	if conn == nil {
		return nil, status.Error(codes.Unavailable, "domain authority unavailable")
	}
	return pb.NewDomainsClient(conn), nil
}
func (r *Remote) Add(ctx context.Context, in *pb.Domain) (*pb.Domain, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.Add(ctx, in)
}
func (r *Remote) List(ctx context.Context, in *pb.Owner) (*pb.DomainList, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.List(ctx, in)
}
func (r *Remote) Verify(ctx context.Context, in *pb.Domain) (*pb.Domain, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	return c.Verify(ctx, in)
}
func (r *Remote) Delete(ctx context.Context, in *pb.Domain) (*emptypb.Empty, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.Delete(ctx, in)
}
func (r *Remote) Route(ctx context.Context, in *pb.Domain) (*pb.Domain, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.Route(ctx, in)
}
func (r *Remote) Certificate(ctx context.Context, in *pb.Domain) (*pb.CertificatePair, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	return c.Certificate(ctx, in)
}
func (r *Remote) Challenge(ctx context.Context, in *pb.ChallengeRequest) (*pb.ChallengeResponse, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.Challenge(ctx, in)
}
