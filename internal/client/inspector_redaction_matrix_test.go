package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// The wire protocol carries request headers as single strings; repeated values
// arrive joined. Response headers are deliberately not retained by the inspector.
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	requestHeaders := map[string]string{
		"aUtHoRiZaTiOn":       strings.Join([]string{secrets[0], "", secrets[0] + "_SECOND"}, ", "),
		"pRoXy-AuThOrIzAtIoN": strings.Join([]string{secrets[1], "", secrets[1] + "_SECOND"}, ", "),
		"cOoKiE":              strings.Join([]string{secrets[2], "", secrets[2] + "_SECOND"}, "; "),
		"sEt-CoOkIe":          strings.Join([]string{secrets[3], "", secrets[3] + "_SECOND"}, ", "),
		"X-Trace-Id":          "trace-normal", "Accept": "application/json",
	}
	client.handleHttpRequest(&mockEstablishTunnelClient{}, &pb.HttpRequest{ConnectionId: "matrix", Method: "GET", Path: "/matrix", Headers: requestHeaders})
	events := inspector.list()
	if len(events) != 1 || events[0].Status != http.StatusAccepted || events[0].At.IsZero() || events[0].DurationMS < 0 {
		t.Fatalf("status or timing missing: %+v", events)
	}
	for _, key := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Trace-Id"} {
		if events[0].Headers[key] != redacted {
			t.Errorf("%s not redacted: %q", key, events[0].Headers[key])
		}
	}
	if events[0].Headers["Accept"] != "application/json" {
		t.Fatal("safe header lost")
	}
	retained, err := json.Marshal(events)
	if err != nil || containsSecret(string(retained)) {
		t.Fatalf("retained capture leaked: %s, %v", retained, err)
	}
	for _, endpoint := range []string{"/api/events", "/api/export"} {
		response := inspectContractAPI(inspector, "GET", endpoint, nil)
		if response.Code != http.StatusOK || containsSecret(response.Body.String()) {
			t.Fatalf("%s leaked or failed: %d %s", endpoint, response.Code, response.Body.String())
		}
	}
	// A failed reconstruction must not echo supplied credentials in its error.
	action := inspectContractAction(t, inspector, events[0].ID)
	_, err = inspector.replay(t.Context(), events[0].ID, inspectionReplayInput{Action: action, Headers: map[string]string{"unexpected": secrets[0]}})
	if err == nil || containsSecret(err.Error()) {
		t.Fatalf("unsafe replay error: %v", err)
	}
}
