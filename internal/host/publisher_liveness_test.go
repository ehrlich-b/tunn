package host

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type livenessTestStream struct {
	mockWebProxyStream
	send func(*pb.TunnelMessage) error
}

func (s *livenessTestStream) Send(m *pb.TunnelMessage) error { return s.send(m) }

func TestPublisherLivenessAdmissionBeforeAuthentication(t *testing.T) {
	// This deliberately needs neither an account authority nor an HTTP origin:
	// an unresponsive publisher must be handled before either is contacted.
	stream := &mockWebProxyStream{}
	tunnel := &TunnelConnection{Stream: stream, Capabilities: map[string]bool{common.CapabilityPublisherLivenessV1: true}}
	proxy := &ProxyServer{tunnelServer: &TunnelServer{tunnels: map[string]*TunnelConnection{"sleeping": tunnel}}}
	for _, cookie := range []string{"", "tunn_auth=synthetic-owner"} {
		req := httptest.NewRequest("GET", "https://sleeping.tunn.to/", nil)
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		started := time.Now()
		if err := proxy.proxyToLocal(rec, req, "sleeping"); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 503 || !strings.Contains(strings.ToLower(rec.Body.String()), "offline") || rec.Header().Get("Location") != "" {
			t.Fatalf("response = %d %v %q", rec.Code, rec.Header(), rec.Body.String())
		}
		if elapsed := time.Since(started); elapsed >= 5*time.Second {
			t.Fatal("visitor timeout", elapsed)
		}
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for _, m := range stream.sentMsgs {
		if m.GetHealthCheck() == nil {
			t.Fatal("visitor was forwarded to origin", m)
		}
	}
}

func TestPublisherLivenessRequiresFreshMatchingResponse(t *testing.T) {
	tunnel := &TunnelConnection{Capabilities: map[string]bool{common.CapabilityPublisherLivenessV1: true}}
	calls := 0
	var previous int64
	tunnel.Stream = &livenessTestStream{send: func(m *pb.TunnelMessage) error {
		calls++
		stamp := m.GetHealthCheck().Timestamp
		if calls == 1 {
			previous = stamp
			tunnel.acknowledgeLiveness(stamp)
		} else {
			// A delayed pong from a completed check must not prove current liveness.
			tunnel.acknowledgeLiveness(previous)
		}
		return nil
	}}
	if !tunnel.publisherLive(context.Background()) {
		t.Fatal("matching response rejected")
	}
	if tunnel.publisherLive(context.Background()) {
		t.Fatal("stale response accepted or live result cached")
	}
	if calls != 2 {
		t.Fatal("checks sent", calls)
	}
}

func TestPublisherLivenessLegacyCompatibility(t *testing.T) {
	if !(&TunnelConnection{}).publisherLive(context.Background()) {
		t.Fatal("legacy publisher rejected")
	}
}

func TestPublisherLivenessCancelledVisitorDoesNotCancelSharedCheck(t *testing.T) {
	tunnel := &TunnelConnection{Capabilities: map[string]bool{common.CapabilityPublisherLivenessV1: true}}
	sent := make(chan int64, 1)
	tunnel.Stream = &livenessTestStream{send: func(m *pb.TunnelMessage) error {
		sent <- m.GetHealthCheck().Timestamp
		return nil
	}}
	result := make(chan bool, 1)
	go func() { result <- tunnel.publisherLive(context.Background()) }()
	stamp := <-sent
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if tunnel.publisherLive(ctx) {
		t.Fatal("cancelled visitor admitted")
	}
	tunnel.acknowledgeLiveness(stamp)
	select {
	case live := <-result:
		if !live {
			t.Fatal("one cancelled visitor interrupted another visitor")
		}
	case <-time.After(time.Second):
		t.Fatal("shared check did not finish")
	}
	select {
	case <-sent:
		t.Fatal("overlapping visitor started a second check")
	default:
	}
}
