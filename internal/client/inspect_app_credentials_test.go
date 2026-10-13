package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestInspectContractAppCredentialsOmitCapturedBody(t *testing.T) {
	var deliveries atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		deliveries.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	for _, prefix := range []string{"tunn_app_", "tunn_inv_"} {
		secret := prefix + "synthetic-private-value"
		inspector := NewInspectorWithBodyCapture(&ServeClient{TargetURL: target.URL}, true)
		capture := inspector.begin("POST", "/hook", nil)
		_, _ = capture.Write([]byte(secret))
		capture.complete()
		capture.finish(200, 0, "")
		event := inspector.list()[0]
		data, _ := json.Marshal(event)
		if strings.Contains(string(data), secret) || len(event.Body) != 0 || event.BodyCaptured || event.Replayable {
			t.Fatal("opt-in capture retained an app credential")
		}
		body := []byte(secret)
		if _, err := inspector.replay(context.Background(), event.ID, inspectionReplayInput{Action: inspectContractAction(t, inspector, event.ID), Body: &body}); err == nil {
			t.Fatal("local inspector replay accepted a credential")
		}
		if deliveries.Load() != 0 {
			t.Fatal("credential replay reached origin")
		}
	}
	inspector := NewInspectorWithBodyCapture(&ServeClient{TargetURL: target.URL}, true)
	capture := inspector.begin("POST", "/hook", nil)
	_, _ = capture.Write([]byte("ordinary fixture body"))
	capture.complete()
	capture.finish(200, 0, "")
	if event := inspector.list()[0]; !event.BodyCaptured || string(event.Body) != "ordinary fixture body" {
		t.Fatal("ordinary opt-in body was discarded")
	}
	event := inspector.list()[0]
	if _, err := inspector.replay(context.Background(), event.ID, inspectionReplayInput{Action: inspectContractAction(t, inspector, event.ID)}); err != nil || deliveries.Load() != 1 {
		t.Fatal("ordinary replay did not reach origin", err)
	}
}
