package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestInspectorCapturesAndReplaysToLocalTarget(t *testing.T) {
	var mu sync.Mutex
	var deliveries []string
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		mu.Lock()
		deliveries = append(deliveries, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("X-Webhook-Test")+" "+body.String())
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("ok"))
	}))
	defer local.Close()

	client := &ServeClient{TargetURL: local.URL}
	inspector := NewInspector(client)
	client.Inspector = inspector
	client.handleHttpRequest(&mockEstablishTunnelClient{}, &pb.HttpRequest{
		ConnectionId: "webhook-1", Method: http.MethodPost, Path: "/webhook?kind=test",
		Headers: map[string]string{"X-Webhook-Test": "signed"}, Body: []byte(`{"event":"created"}`),
	})
	events := inspector.list()
	if len(events) != 1 || events[0].Status != http.StatusAccepted || !events[0].Replayable || events[0].RequestBytes != int64(len(events[0].Body)) {
		t.Fatalf("unexpected captured delivery: %+v", events)
	}
	if _, err := inspector.replay(context.Background(), events[0].ID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deliveries) != 2 || deliveries[0] != deliveries[1] {
		t.Fatalf("replay differed from original: %q", deliveries)
	}
	events = inspector.list()
	if events[1].ReplayOf != events[0].ID || events[1].Status != http.StatusAccepted {
		t.Fatalf("replay result not labeled: %+v", events[1])
	}
}

func TestInspectorRejectsTruncatedReplay(t *testing.T) {
	inspector := NewInspector(&ServeClient{TargetURL: "http://127.0.0.1:1"})
	capture := inspector.begin(http.MethodPost, "/webhook", nil)
	_, _ = capture.Write(bytes.Repeat([]byte("x"), inspectBodyLimit+1))
	capture.complete()
	capture.finish(http.StatusOK, 0, "")
	event := inspector.list()[0]
	if !event.Truncated || event.Replayable || len(event.Body) != inspectBodyLimit {
		t.Fatalf("truncation state: %+v", event)
	}
	if _, err := inspector.replay(context.Background(), event.ID); err == nil {
		t.Fatal("truncated request could be replayed")
	}
}

func TestInspectorStreamingCaptureAndReplayProtection(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = new(bytes.Buffer).ReadFrom(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer local.Close()
	client := &ServeClient{TargetURL: local.URL}
	inspector := NewInspector(client)
	client.Inspector = inspector
	client.handleStreamingHTTPRequest(context.Background(), &mockEstablishTunnelClient{}, &pb.ConnectionOpen{
		ConnectionId: "stream-webhook", Protocol: "http", HttpRequest: &pb.HttpRequestHead{
			Method: http.MethodPost, Path: "/hook", Headers: map[string]string{"Content-Type": "application/json"},
		},
	}, strings.NewReader(`{"hello":"world"}`))
	events := inspector.list()
	if len(events) != 1 || !events[0].Replayable || events[0].Status != http.StatusNoContent || string(events[0].Body) != `{"hello":"world"}` {
		t.Fatalf("stream capture: %+v", events)
	}

	incomplete := inspector.begin(http.MethodPost, "/hook", nil)
	reader := &inspectionReader{reader: strings.NewReader("partial"), capture: incomplete}
	buffer := make([]byte, 3)
	_, _ = reader.Read(buffer)
	incomplete.finish(http.StatusBadGateway, 0, "failed to forward")
	if inspector.list()[1].Replayable {
		t.Fatal("partial streamed request could be replayed")
	}
}

func TestInspectorHTTPRequiresExactHostAndReplayToken(t *testing.T) {
	inspector := NewInspector(&ServeClient{TargetURL: "http://127.0.0.1:1"})
	inspector.host = "127.0.0.1:4040"
	inspector.token = "test-token"
	capture := inspector.begin(http.MethodPost, "/hook", nil)
	capture.complete()
	capture.finish(http.StatusOK, 0, "")

	request := httptest.NewRequest(http.MethodGet, "http://evil.test/api/events", nil)
	response := httptest.NewRecorder()
	inspector.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("host check status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:4040/api/events/1/replay", nil)
	response = httptest.NewRecorder()
	inspector.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing token status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:4040/api/events", nil)
	response = httptest.NewRecorder()
	inspector.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing read token status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:4040/api/events", nil)
	request.Header.Set("X-Tunn-Inspector-Token", inspector.token)
	response = httptest.NewRecorder()
	inspector.ServeHTTP(response, request)
	var events []InspectionEvent
	if err := json.Unmarshal(response.Body.Bytes(), &events); err != nil || len(events) != 1 {
		t.Fatalf("event API response: %s: %v", response.Body.String(), err)
	}
}

func TestInspectorStartsOnLoopbackWithSessionSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inspector := NewInspector(&ServeClient{})
	viewerURL, err := inspector.StartInspector(ctx)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(viewerURL)
	if err != nil || parsed.Hostname() != "127.0.0.1" || len(parsed.Fragment) != 64 {
		t.Fatalf("viewer URL = %q: %v", viewerURL, err)
	}
	response, err := http.Get("http://" + parsed.Host + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized viewer status = %d", response.StatusCode)
	}
}
