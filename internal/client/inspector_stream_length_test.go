package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestInspectorStreamingBodyLengthSemantics(t *testing.T) {
	const body = `{"hello":"world"}`
	for _, test := range []struct {
		name          string
		body          string
		contentLength int64
		readBytes     int // Negative reads through EOF; zero leaves the body unread.
		complete      bool
	}{
		{name: "empty unread", contentLength: 0, complete: true},
		{name: "zero length complete", body: body, contentLength: 0, readBytes: -1, complete: true},
		{name: "zero length partial", body: body, contentLength: 0, readBytes: 3},
		{name: "known length without EOF", body: body, contentLength: int64(len(body)), readBytes: len(body), complete: true},
		{name: "known length partial", body: body, contentLength: int64(len(body)), readBytes: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			var consumed []byte
			client := &ServeClient{TargetURL: "http://fixture.test", HTTPTransport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var err error
				if test.readBytes < 0 {
					consumed, err = io.ReadAll(r.Body)
				} else if test.readBytes > 0 {
					consumed = make([]byte, test.readBytes)
					_, err = io.ReadFull(r.Body, consumed)
				}
				if err != nil {
					return nil, err
				}
				return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
			})}
			client.Inspector = NewInspectorWithBodyCapture(client, true)
			client.handleStreamingHTTPRequest(context.Background(), inspectContractSender{}, &pb.ConnectionOpen{
				ConnectionId: "stream-length", Protocol: "http", HttpRequest: &pb.HttpRequestHead{
					Method: http.MethodPost, Path: "/hook", ContentLength: test.contentLength,
				},
			}, strings.NewReader(test.body))
			events := client.Inspector.list()
			if len(events) != 1 {
				t.Fatalf("events = %+v", events)
			}
			event := events[0]
			if event.Status != http.StatusNoContent || event.BodyComplete != test.complete || event.Replayable != test.complete || event.RequestBytes != int64(len(consumed)) || string(event.Body) != string(consumed) {
				t.Fatalf("stream capture = %+v", event)
			}
		})
	}
}
