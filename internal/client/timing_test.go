package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/inspection"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
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

// A missing relay close retains only metadata until the existing stream ends.
func TestRequestTimingMissingRelayCloseReleasesSlot(t *testing.T) {
	for _, shutdown := range []string{"cancel", "close-all"} {
		t.Run(shutdown, func(t *testing.T) {
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
			waitRequestTimingOriginEOF(t, manager, "missing-close", 2*time.Second)
			if events := publisher.Inspector.Events(); len(events) != 0 {
				t.Fatalf("history finalized before delivery or stream end: %+v", events)
			}
			manager.mu.RLock()
			pending := manager.timings["missing-close"] != nil
			manager.mu.RUnlock()
			if !pending {
				t.Fatal("origin EOF discarded pending timing")
			}

			// The single slot is immediately available without a relay close.
			manager.open(ctx, publisher, sender, &pb.ConnectionOpen{
				ConnectionId: "next", Protocol: "http",
				HttpRequest: &pb.HttpRequestHead{Method: http.MethodGet, Path: "/next"},
			})
			manager.halfClose("next")
			waitRequestTimingOriginEOF(t, manager, "next", 2*time.Second)
			if events := publisher.Inspector.Events(); len(events) != 1 || events[0].Status != 200 || events[0].ConnectionID != "next" {
				t.Fatalf("capacity not reusable at origin EOF: %+v", events)
			}

			if shutdown == "cancel" {
				cancel()
			} else {
				manager.closeAll(io.EOF)
			}
			done := make(chan struct{})
			go func() { manager.workers.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("timing worker outlived stream shutdown")
			}
			manager.mu.RLock()
			pendingCount := len(manager.timings)
			manager.mu.RUnlock()
			if pendingCount != 0 {
				t.Fatal("stream shutdown retained timing metadata")
			}
			events := publisher.Inspector.Events()
			if len(events) != 2 || events[1].ConnectionID != "missing-close" || events[1].TerminalReason != "canceled" || events[1].Timing != nil {
				t.Fatalf("stream shutdown should finish with unavailable timing: %+v", events)
			}
		})
	}
}

func TestRequestTimingResponseBeforeUploadEOF(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Consume one byte while the publisher keeps the upload open.
		if _, err := io.ReadFull(r.Body, make([]byte, 1)); err != nil {
			t.Error(err)
			return
		}
		time.Sleep(1100 * time.Millisecond)
		// Avoid HTTP/1's automatic request-body drain before the response.
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusAccepted)
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
		ConnectionId: "early-response", Protocol: "http", RequestTiming: true,
		HttpRequest: &pb.HttpRequestHead{Method: http.MethodPost, Path: "/", ContentLength: 2},
	})
	manager.write("early-response", []byte("a"))
	// No half-close: the origin responds before the second byte or upload EOF.
	waitRequestTimingOriginEOF(t, manager, "early-response", 5*time.Second)
	var head *pb.HttpResponseHead
	var halfClose *pb.ConnectionHalfClose
	for i := 0; i < sender.getSentCount(); i++ {
		message := sender.getSentMsg(i)
		if accept := message.GetConnectionAccept(); accept != nil {
			if !accept.Success {
				t.Fatalf("origin response rejected: %+v", accept)
			}
			head = accept.HttpResponse
		}
		if closed := message.GetConnectionHalfClose(); closed != nil {
			halfClose = closed
		}
	}
	if head == nil || head.StatusCode != http.StatusAccepted || halfClose == nil {
		t.Fatalf("early response did not complete: head=%+v half-close=%+v", head, halfClose)
	}
	if head.OriginTtfbUs != 0 || head.OriginTotalUs != 0 || halfClose.OriginTotalUs != 0 {
		t.Fatalf("fabricated app timing before upload EOF: head=%+v half-close=%+v", head, halfClose)
	}
	// With no origin measurements the relay cannot derive an app/tunnel split.
	manager.complete(&pb.ConnectionClose{ConnectionId: "early-response"})
	manager.workers.Wait()
	events := publisher.Inspector.Events()
	if len(events) != 1 || events[0].TerminalReason != "complete" || events[0].Timing != nil {
		t.Fatalf("early response must omit app timing: %+v", events)
	}
	t.Log("origin returned 202 after 1.1 s before upload EOF; app timing omitted")
}

func waitRequestTimingOriginEOF(t *testing.T, manager *inboundConnectionManager, connectionID string, timeout time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		if manager.get(connectionID) == nil && len(manager.slots) == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("origin EOF did not release publisher capacity promptly")
}
