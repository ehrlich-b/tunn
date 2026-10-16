package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/ehrlich-b/tunn/internal/inspection"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"testing"
)

func TestRequestTimingHistoryIsolation(t *testing.T) {
	inspector := NewInspector(&ServeClient{TargetURL: "http://origin.test"})
	inspector.OnEvent = func(event InspectionEvent, _ InspectionMetrics) { event.Timing.OriginTotalMS = 999 }
	original := inspection.NewTiming(10, 20, 30, 40)
	event := inspector.add(InspectionEvent{ConnectionID: "connection", Timing: original})
	original.OriginTotalMS = 888
	event.Timing.OriginTotalMS = 777
	first := inspector.Events()
	first[0].Timing.OriginTotalMS = 666
	if got := inspector.Events()[0].Timing.OriginTotalMS; got != .02 {
		t.Fatalf("caller, callback or snapshot changed history: %v", got)
	}
}

// A missing best-effort relay close must not retain publisher capacity for a minute.
func TestRequestTimingMissingRelayCloseReleasesSlot(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	ctx, cancel := context.WithCancel(context.Background())
	manager := newInboundConnectionManagerWithLimit(1)
	defer func() {
		cancel()
		manager.closeAll(io.EOF)
		manager.workers.Wait()
	}()
	publisher := &ServeClient{TargetURL: origin.URL}
	publisher.Inspector = NewInspector(publisher)
	sender := &mockEstablishTunnelClient{}
	manager.open(ctx, publisher, sender, &pb.ConnectionOpen{
		ConnectionId: "missing-close", Protocol: "http", RequestTiming: true,
		HttpRequest: &pb.HttpRequestHead{Method: http.MethodGet, Path: "/"},
	})
	manager.halfClose("missing-close")
	done := make(chan struct{})
	go func() { manager.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("missing relay close retained publisher connection slot")
	}
	if manager.get("missing-close") != nil || len(manager.slots) != 0 {
		t.Fatal("completed request retained publisher connection slot")
	}
	events := publisher.Inspector.Events()
	if len(events) != 1 || events[0].TerminalReason != "complete" || events[0].Timing != nil {
		t.Fatalf("missing close should complete with unavailable timing: %+v", events)
	}
}
