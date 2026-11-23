package client

import (
	"context"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestPublisherLivenessRespondsWithoutOrigin(t *testing.T) {
	stream := &mockEstablishTunnelClient{recvMsgs: []*pb.TunnelMessage{{Message: &pb.TunnelMessage_HealthCheck{
		HealthCheck: &pb.HealthCheck{Timestamp: 123456},
	}}}}
	s := &ServeClient{TargetURL: "http://unreachable.invalid"}
	_ = s.processMessages(context.Background(), stream, stream)
	if stream.getSentCount() != 1 {
		t.Fatal("messages", stream.getSentCount())
	}
	pong := stream.getSentMsg(0).GetHealthCheckResponse()
	if pong == nil || pong.Timestamp != 123456 || pong.ResponseTimestamp == 0 {
		t.Fatal("pong", pong)
	}
}
