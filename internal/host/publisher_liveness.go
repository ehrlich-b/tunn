package host

import (
	"context"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Bound admission independently of upstream response timeouts. A publisher
// must answer without contacting its origin, including for denied visitors.
const publisherLivenessTimeout = 2 * time.Second

type publisherLivenessProbe struct {
	timestamp int64
	ack       chan struct{}
	done      chan struct{}
	live      bool
}

func (t *TunnelConnection) publisherLive(ctx context.Context) bool {
	if !t.Supports(common.CapabilityPublisherLivenessV1) {
		return true // Older publishers retain their existing transport detection.
	}
	t.livenessMu.Lock()
	probe := t.liveness
	if probe == nil {
		t.livenessSequence = max(time.Now().UnixMilli(), t.livenessSequence+1)
		probe = &publisherLivenessProbe{timestamp: t.livenessSequence, ack: make(chan struct{}, 1), done: make(chan struct{})}
		t.liveness = probe
		go t.checkPublisherLiveness(probe)
	}
	t.livenessMu.Unlock()
	select {
	case <-ctx.Done():
		return false
	case <-probe.done:
		return probe.live
	}
}

func (t *TunnelConnection) checkPublisherLiveness(probe *publisherLivenessProbe) {
	// One cancelled visitor must not cancel checks shared by other visitors.
	ctx, cancel := context.WithTimeout(t.Stream.Context(), publisherLivenessTimeout)
	defer cancel()
	err := t.SendMessageContext(ctx, &pb.TunnelMessage{Message: &pb.TunnelMessage_HealthCheck{
		HealthCheck: &pb.HealthCheck{Timestamp: probe.timestamp},
	}})
	if err == nil {
		select {
		case <-probe.ack:
			probe.live = true
		case <-ctx.Done():
		}
	}
	t.livenessMu.Lock()
	t.liveness = nil
	close(probe.done)
	t.livenessMu.Unlock()
}

func (t *TunnelConnection) acknowledgeLiveness(timestamp int64) {
	t.livenessMu.Lock()
	defer t.livenessMu.Unlock()
	if probe := t.liveness; probe != nil && probe.timestamp == timestamp {
		select {
		case probe.ack <- struct{}{}:
		default:
		}
	}
}
