package client

import (
	"context"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"io"
	"testing"
	"time"
)

func TestHostClientPersistentEOF(t *testing.T) {
	stream := &hostEOFStream{}
	if err := (&ServeClient{Persistent: true}).processMessages(context.Background(), stream, stream); err == nil {
		t.Fatal("persistent publisher treated relay EOF as a completed session")
	}
	if err := (&ServeClient{}).processMessages(context.Background(), stream, stream); err != nil {
		t.Fatalf("ordinary publisher EOF behavior changed: %v", err)
	}
}

func TestReconnectBackoffBounds(t *testing.T) {
	for _, initial := range []time.Duration{time.Nanosecond, time.Second, time.Minute} {
		for attempt := 0; attempt < 100; attempt++ {
			cap := min(initial, 30*time.Second)
			for i := 0; i < attempt && cap < 30*time.Second; i++ {
				cap = min(cap*2, 30*time.Second)
			}
			for _, sample := range []float64{-1, 0, .25, .5, 1, 2} {
				got := reconnectDelay(initial, 30*time.Second, attempt, sample)
				if got < cap/2 || got > cap {
					t.Fatalf("attempt %d: delay %s outside [%s,%s]", attempt, got, cap/2, cap)
				}
			}
		}
	}
	if got := reconnectDelay(time.Second, 30*time.Second, 0, .5); got != 750*time.Millisecond {
		t.Fatalf("initial jitter = %s", got)
	}
	if a, b := reconnectDelay(time.Second, 30*time.Second, 4, 0), reconnectDelay(time.Second, 30*time.Second, 4, 1); a == b {
		t.Fatal("backoff has no jitter")
	}
	if got := reconnectDelay(time.Duration(1<<62), time.Duration(1<<63-1), 1000000, 1); got <= 0 {
		t.Fatal("backoff overflowed")
	}
}

type hostEOFStream struct{ mockEstablishTunnelClient }

func (*hostEOFStream) Recv() (*pb.TunnelMessage, error) { return nil, io.EOF }
