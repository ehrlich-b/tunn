package consumer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	tunn "github.com/ehrlich-b/tunn/sdk"
)

func TestExternalConsumer(t *testing.T) {
	// A canceled lifetime proves both entry points are callable outside the
	// module without connecting to a relay or reading local account credentials.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := tunn.Options{Origin: "http://127.0.0.1:8080", Credentials: tunn.Credentials{AuthToken: "consumer-fixture"}, Reconnect: &tunn.ReconnectPolicy{MaxAttempts: 0}}
	if _, err := tunn.Publish(ctx, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("Publish: %v", err)
	}
	o.Origin = ""
	if _, err := tunn.PublishHandler(ctx, http.NotFoundHandler(), o); !errors.Is(err, context.Canceled) {
		t.Fatalf("PublishHandler: %v", err)
	}
	var publish func(context.Context, tunn.Options) (*tunn.Tunnel, error) = tunn.Publish
	var handler func(context.Context, http.Handler, tunn.Options) (*tunn.Tunnel, error) = tunn.PublishHandler
	_, _ = publish, handler
}

// streamingExample is an ordinary handler owned by the importing application.
// Declared trailers need both peers to support http-response-trailers-v1.
func streamingExample(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "first", Value: "one,fragment=two", Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "second", Value: "three", Path: "/"})
	w.Header().Add("Trailer", "X-Stream-End")
	w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(w, "prefix\n")
	if err := http.NewResponseController(w).Flush(); err != nil {
		return
	}
	_, _ = io.WriteString(w, "suffix\n")
	w.Header().Set("X-Stream-End", "complete")
}

func TestExternalResponseHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	handler := http.HandlerFunc(streamingExample)
	options := tunn.Options{Credentials: tunn.Credentials{AuthToken: "consumer-fixture"}, Reconnect: &tunn.ReconnectPolicy{MaxAttempts: 0}}
	if _, err := tunn.PublishHandler(ctx, handler, options); !errors.Is(err, context.Canceled) {
		t.Fatalf("PublishHandler response example: %v", err)
	}
	// No relay or TCP listener is used by this standalone importer. Transport
	// guarantees are exercised independently by the main memory fixture gate.
	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, httptest.NewRequest("GET", "http://consumer.invalid/", nil))
	response := writer.Result()
	defer response.Body.Close()
	if response.StatusCode != 202 || len(response.Cookies()) != 2 || response.Cookies()[0].Value != "one,fragment=two" || !writer.Flushed || writer.Body.String() != "prefix\nsuffix\n" || response.Trailer.Get("X-Stream-End") != "complete" {
		t.Fatalf("consumer response: %d %v %v %q", response.StatusCode, response.Header, response.Trailer, writer.Body.String())
	}
}
