package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Response headers are deliberately not retained by the inspector.
func TestInspectorRedactionMatrix(t *testing.T) {
	secrets := []string{"REQUEST_AUTH_CANARY", "REQUEST_PROXY_CANARY", "REQUEST_COOKIE_CANARY", "REQUEST_SET_COOKIE_CANARY", "RESPONSE_AUTH_CANARY", "RESPONSE_PROXY_CANARY", "RESPONSE_COOKIE_CANARY", "RESPONSE_SET_COOKIE_CANARY"}
	containsSecret := func(s string) bool {
		for _, secret := range secrets {
			if strings.Contains(s, secret) {
				return true
			}
		}
		return false
	}
	if !containsSecret(secrets[0]) {
		t.Fatal("negative control failed")
	}
	responseHeaders := http.Header{
		"aUtHoRiZaTiOn":       {secrets[4], "", secrets[4] + "_SECOND"},
		"pRoXy-AuThOrIzAtIoN": {secrets[5], "", secrets[5] + "_SECOND"},
		"cOoKiE":              {secrets[6], "", secrets[6] + "_SECOND"},
		"sEt-CoOkIe":          {secrets[7], "", secrets[7] + "_SECOND"},
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		for key, values := range responseHeaders {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	client := &ServeClient{TargetURL: server.URL}
	inspector := NewInspector(client)
	inspector.host, inspector.token = "127.0.0.1:4040", "fixture-token"
	client.Inspector = inspector
	fields := []*pb.HttpHeader{
		{Name: "aUtHoRiZaTiOn", Value: secrets[0]},
		{Name: "pRoXy-AuThOrIzAtIoN", Value: secrets[1]},
		{Name: "cOoKiE", Value: secrets[2]}, {Name: "COOKIE", Value: ""}, {Name: "cookie", Value: secrets[2] + "_SECOND"},
		{Name: "sEt-CoOkIe", Value: secrets[3]}, {Name: "set-cookie", Value: ""}, {Name: "Set-Cookie", Value: secrets[3] + "_SECOND"},
		{Name: "X-Trace-Id", Value: "trace-normal"}, {Name: "Accept", Value: "application/json"},
	}
	legacy := map[string]string{"Accept": "text/plain"} // Field arrays take precedence.
	client.handleHttpRequest(&mockEstablishTunnelClient{}, &pb.HttpRequest{ConnectionId: "buffered", Method: "GET", Path: "/matrix", Headers: legacy, HeaderFields: fields})
	client.handleStreamingHTTPRequest(context.Background(), &mockEstablishTunnelClient{}, &pb.ConnectionOpen{ConnectionId: "stream", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/matrix", Headers: legacy, HeaderFields: fields}}, strings.NewReader(""))
	events := inspector.list()
	checkEvents := func(events []InspectionEvent) {
		t.Helper()
		if len(events) != 2 {
			t.Fatalf("expected two captures, got %+v", events)
		}
		for _, event := range events {
			if event.Status != http.StatusAccepted || event.At.IsZero() || event.DurationMS < 0 || event.Replayable || event.Reconstructable {
				t.Fatalf("status, timing or replay safety: %+v", event)
			}
			for _, key := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Trace-Id"} {
				if event.Headers[key] != redacted {
					t.Errorf("%s not redacted: %q", key, event.Headers[key])
				}
			}
			if event.Headers["Accept"] != "application/json" {
				t.Fatalf("safe header lost: %+v", event.Headers)
			}
		}
	}
	checkEvents(events)
	retained, err := json.Marshal(events)
	if err != nil || containsSecret(string(retained)) {
		t.Fatalf("retained capture leaked: %s, %v", retained, err)
	}
	for _, endpoint := range []string{"/api/events", "/api/export"} {
		response := inspectContractAPI(inspector, "GET", endpoint, nil)
		if response.Code != http.StatusOK || containsSecret(response.Body.String()) {
			t.Fatalf("%s leaked or failed: %d %s", endpoint, response.Code, response.Body.String())
		}
		var exported []InspectionEvent
		if endpoint == "/api/events" {
			err = json.Unmarshal(response.Body.Bytes(), &exported)
		} else {
			var envelope struct {
				Events []InspectionEvent `json:"events"`
			}
			err = json.Unmarshal(response.Body.Bytes(), &envelope)
			exported = envelope.Events
		}
		if err != nil {
			t.Fatal(err)
		}
		checkEvents(exported)
	}
	// Repeated singleton fields are rejected before dispatch but still sanitized.
	for _, name := range []string{"Authorization", "Proxy-Authorization"} {
		bad := []*pb.HttpHeader{{Name: name, Value: secrets[0]}, {Name: strings.ToLower(name), Value: secrets[1]}}
		client.handleHttpRequest(&mockEstablishTunnelClient{}, &pb.HttpRequest{ConnectionId: "bad", Method: "GET", Path: "/", HeaderFields: bad})
		client.handleStreamingHTTPRequest(context.Background(), &mockEstablishTunnelClient{}, &pb.ConnectionOpen{ConnectionId: "bad-stream", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/", HeaderFields: bad}}, strings.NewReader(""))
	}
	if calls.Load() != 2 {
		t.Fatalf("rejected requests reached origin: %d calls", calls.Load())
	}
	for _, event := range inspector.list()[2:] {
		data, err := json.Marshal(event)
		if err != nil || containsSecret(string(data)) || event.Status == http.StatusAccepted || event.Replayable || event.Reconstructable {
			t.Fatalf("unsafe rejected capture: %s %v", data, err)
		}
	}
	// A failed reconstruction must not echo supplied credentials in its error.
	capture := inspector.begin("GET", "/replay", map[string]string{"Authorization": secrets[0]})
	capture.complete()
	replayEvent := capture.finishReason(http.StatusOK, 0, "complete")
	action := inspectContractAction(t, inspector, replayEvent.ID)
	_, err = inspector.replay(t.Context(), replayEvent.ID, inspectionReplayInput{Action: action, Headers: map[string]string{"unexpected": secrets[0]}})
	if err == nil || containsSecret(err.Error()) {
		t.Fatalf("unsafe replay error: %v", err)
	}
}
