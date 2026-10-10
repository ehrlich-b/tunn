package sshfront

import (
	"context"
	"io"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// Stream is an in-process control stream. Only its host-side callback can attach
// a trusted identity; no network metadata is accepted as proof of SSH identity.
type Stream struct {
	ctx               context.Context
	inbound, outbound chan *pb.TunnelMessage
}

func NewStream(ctx context.Context) (*Stream, *Messages) {
	a, b := make(chan *pb.TunnelMessage, 16), make(chan *pb.TunnelMessage, 16)
	return &Stream{ctx: ctx, inbound: a, outbound: b}, &Messages{ctx: ctx, inbound: b, outbound: a}
}
func send(ctx context.Context, ch chan<- *pb.TunnelMessage, m *pb.TunnelMessage) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case ch <- m:
		return nil
	}
}
func recv(ctx context.Context, ch <-chan *pb.TunnelMessage) (*pb.TunnelMessage, error) {
	select {
	case <-ctx.Done():
		return nil, io.EOF
	case m := <-ch:
		return m, nil
	}
}
func (s *Stream) Send(m *pb.TunnelMessage) error   { return send(s.ctx, s.outbound, m) }
func (s *Stream) Recv() (*pb.TunnelMessage, error) { return recv(s.ctx, s.inbound) }
func (s *Stream) Context() context.Context         { return s.ctx }
func (s *Stream) SetHeader(metadata.MD) error      { return nil }
func (s *Stream) SendHeader(metadata.MD) error     { return nil }
func (s *Stream) SetTrailer(metadata.MD)           {}
func (s *Stream) SendMsg(m any) error              { return s.Send(m.(*pb.TunnelMessage)) }
func (s *Stream) RecvMsg(m any) error {
	v, e := s.Recv()
	if e == nil {
		proto.Reset(m.(*pb.TunnelMessage))
		proto.Merge(m.(*pb.TunnelMessage), v)
	}
	return e
}

type Messages struct {
	ctx               context.Context
	inbound, outbound chan *pb.TunnelMessage
	Observe           func(*pb.TunnelMessage)
}

func (s *Messages) Send(m *pb.TunnelMessage) error {
	if s.Observe != nil {
		s.Observe(m)
	}
	return send(s.ctx, s.outbound, m)
}
func (s *Messages) Recv() (*pb.TunnelMessage, error) {
	m, e := recv(s.ctx, s.inbound)
	if e == nil && s.Observe != nil {
		s.Observe(m)
	}
	return m, e
}
