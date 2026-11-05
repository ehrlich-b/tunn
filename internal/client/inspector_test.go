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
	inspector := NewInspectorWithBodyCapture(client, true)
	client.Inspector = inspector
	client.handleHttpRequest(&mockEstablishTunnelClient{}, &pb.HttpRequest{
		ConnectionId: "webhook-1", Method: http.MethodPost, Path: "/webhook?kind=test",
		Headers: map[string]string{"X-Webhook-Test": "signed"}, Body: []byte(`{"event":"created"}`),
	})
	events := inspector.list()
	if len(events) != 1 || events[0].Status != http.StatusAccepted || !events[0].Reconstructable || events[0].Replayable || events[0].Headers["X-Webhook-Test"] != redacted || events[0].RequestBytes != int64(len(events[0].Body)) {
		t.Fatalf("unexpected captured delivery: %+v", events)
	}
	replayPath := "/webhook?kind=test"
	if _, err := inspector.replay(context.Background(), events[0].ID, inspectionReplayInput{Action: inspectContractAction(t, inspector, events[0].ID), Path: &replayPath, Headers: map[string]string{"X-Webhook-Test": "signed"}}); err != nil {
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
	inspector := NewInspectorWithBodyCapture(&ServeClient{TargetURL: "http://127.0.0.1:1"}, true)
	capture := inspector.begin(http.MethodPost, "/webhook", nil)
	_, _ = capture.Write(bytes.Repeat([]byte("x"), inspectBodyLimit+1))
	capture.complete()
	capture.finish(http.StatusOK, 0, "")
	event := inspector.list()[0]
	if !event.Truncated || event.Replayable || len(event.Body) != inspectBodyLimit {
		t.Fatalf("truncation state: %+v", event)
	}
	if _, err := inspector.replay(context.Background(), event.ID, inspectionReplayInput{Action: "invalid"}); err == nil {
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
	inspector := NewInspectorWithBodyCapture(client, true)
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
	inspector := NewInspectorWithBodyCapture(&ServeClient{TargetURL: "http://127.0.0.1:1"}, true)
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

func TestInspectorReplaysRepeatedHeaders(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Values("X-Delivery"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
			t.Errorf("origin headers = %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer local.Close()
	for _, streaming := range []bool{false, true} {
		client := &ServeClient{TargetURL: local.URL}
		client.Inspector = NewInspectorWithBodyCapture(client, true)
		fields := []*pb.HttpHeader{{Name: "X-Delivery", Value: "one"}, {Name: "x-delivery", Value: "two"}}
		legacy := map[string]string{"X-Delivery": "one, two"}
		if streaming {
			client.handleStreamingHTTPRequest(context.Background(), &mockEstablishTunnelClient{}, &pb.ConnectionOpen{ConnectionId: "stream", HttpRequest: &pb.HttpRequestHead{Method: "POST", Path: "/", Headers: legacy, HeaderFields: fields}}, strings.NewReader(""))
		} else {
			client.handleHttpRequest(&mockEstablishTunnelClient{}, &pb.HttpRequest{ConnectionId: "buffered", Method: "POST", Path: "/", Headers: legacy, HeaderFields: fields})
		}
		event := client.Inspector.list()[0]
		if event.MetadataTruncated || !event.Reconstructable || event.Replayable {
			t.Fatalf("streaming=%v: unsafe replay state: %+v", streaming, event)
		}
		if _, err := client.Inspector.Replay(context.Background(), event.ID); err == nil {
			t.Fatal("redacted repeated fields replayed without reconstruction")
		}
		input := InspectionReplayRequest{Headers: map[string]string{"X-Delivery": "two"}, HeaderValues: map[string][]string{"X-Delivery": {"one", "two"}}}
		result, err := client.Inspector.ReplayWithRequest(context.Background(), event.ID, input)
		if err != nil || result.Status != 200 || result.ReplayOf != event.ID {
			t.Fatalf("replay: %+v %v", result, err)
		}
		if got := client.Inspector.repeated[result.ID]["X-Delivery"]; len(got) != 2 || got[0] != redacted || got[1] != redacted {
			t.Fatalf("replay retained raw repeated values: %q", got)
		}
		input.HeaderValues["X-Delivery"] = []string{"two"}
		if _, err := client.Inspector.ReplayWithRequest(context.Background(), event.ID, input); err == nil {
			t.Fatal("lossy reconstruction accepted")
		}
	}
}

func TestInspectorCapturesFieldOnlyHeaders(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer local.Close()
	for _, streaming := range []bool{false, true} {
		client := &ServeClient{TargetURL: local.URL}
		client.Inspector = NewInspectorWithBodyCapture(client, true)
		fields := []*pb.HttpHeader{{Name: "Stripe-Signature", Value: "fixture-secret"}}
		if streaming {
			client.handleStreamingHTTPRequest(context.Background(), &mockEstablishTunnelClient{}, &pb.ConnectionOpen{ConnectionId: "stream", HttpRequest: &pb.HttpRequestHead{Method: "POST", Path: "/", HeaderFields: fields}}, strings.NewReader(""))
		} else {
			client.handleHttpRequest(&mockEstablishTunnelClient{}, &pb.HttpRequest{ConnectionId: "buffered", Method: "POST", Path: "/", HeaderFields: fields})
		}
		event := client.Inspector.list()[0]
		if event.Headers["Stripe-Signature"] != redacted || event.Replayable || !event.Reconstructable {
			t.Fatalf("streaming=%v: field-only signature metadata: %+v", streaming, event)
		}
	}
}

func TestInspectorRepeatedHeaderSafeguards(t *testing.T) {
	for _, values := range [][]string{{"text/plain", "application/json"}, {"tunn_ep_secret", "application/json"}} {
		inspector := NewInspectorWithBodyCapture(&ServeClient{}, true)
		capture := inspector.begin("POST", "/", map[string]string{"Accept": values[1]})
		capture.checkHeaderFields([]*pb.HttpHeader{{Name: "Accept", Value: values[0]}, {Name: "accept", Value: values[1]}})
		capture.complete()
		event := capture.finishReason(200, 0, "complete")
		repeated := inspector.repeated[event.ID]
		if strings.HasPrefix(values[0], "tunn_ep_") {
			if event.Headers["Accept"] != redacted || repeated.Get("Accept") != redacted || event.Replayable {
				t.Fatal("earlier credential value escaped redaction")
			}
			continue
		}
		result, err := reconstructRepeated(repeated, inspectionReplayInput{})
		if err != nil || len(result["Accept"]) != 2 || result["Accept"][0] != values[0] {
			t.Fatalf("safe repeated values lost: %v %v", result, err)
		}
		result["Accept"][0] = "changed"
		if inspector.repeated[event.ID]["Accept"][0] != values[0] {
			t.Fatal("replay aliases stored fields")
		}
		for _, bad := range [][]string{{"changed", values[1]}, {"tunn_ep_secret", values[1]}, {"a\r\nb", values[1]}, {values[0]}} {
			_, err := reconstructRepeated(repeated, inspectionReplayInput{Headers: map[string]string{"Accept": values[1]}, HeaderValues: map[string][]string{"Accept": bad}})
			if err == nil {
				t.Fatalf("accepted invalid values: %q", bad)
			}
		}
		for j := 0; j < inspectEventLimit; j++ {
			inspector.add(InspectionEvent{})
		}
		if len(inspector.repeated) != 0 {
			t.Fatal("evicted repeated fields retained")
		}
	}
}
