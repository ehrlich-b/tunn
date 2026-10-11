package tunn

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// observeResponse extends the existing memory TLS/gRPC fixture, keeping the
// real SDK HTTP pipe and client serializer in both modes.
type observedResponse struct {
	status  int
	headers map[string]string
	body    string
	frames  []*pb.TunnelMessage
	err     error
}

func observeResponse(t *testing.T, mode, method string, handler http.Handler) observedResponse {
	t.Helper()
	result := make(chan observedResponse, 1)
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) (err error) {
		var got observedResponse
		defer func() {
			if err != nil {
				got.err = err
				result <- got
			}
		}()
		reg, err := registration(stream)
		if err != nil {
			return err
		}
		if err = acceptRegistration(stream, reg); err != nil {
			return err
		}
		if mode == "buffered" {
			err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: "fidelity", Method: method, Path: "/"}}})
		} else {
			err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: &pb.ConnectionOpen{ConnectionId: "fidelity", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: method, Path: "/"}}}})
			if err == nil {
				err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: "fidelity"}}})
			}
		}
		if err != nil {
			return err
		}
		for {
			message, receiveErr := stream.Recv()
			if receiveErr != nil {
				return receiveErr
			}
			got.frames = append(got.frames, message)
			switch {
			case message.GetHttpResponse() != nil:
				response := message.GetHttpResponse()
				got.status, got.headers, got.body = int(response.StatusCode), response.Headers, string(response.Body)
				result <- got
				return drainUntilCanceled(stream)
			case message.GetConnectionAccept() != nil:
				accept := message.GetConnectionAccept()
				if !accept.Success || accept.HttpResponse == nil {
					return fmt.Errorf("response rejected: %s", accept.ErrorMessage)
				}
				got.status, got.headers = int(accept.HttpResponse.StatusCode), accept.HttpResponse.Headers
			case message.GetConnectionData() != nil:
				got.body += string(message.GetConnectionData().Data)
			case message.GetConnectionHalfClose() != nil, message.GetConnectionClose() != nil:
				result <- got
				return drainUntilCanceled(stream)
			}
		}
	})
	o := fixtureOptions()
	o.Origin, o.TLSConfig = "http://sdk-handler.invalid", tlsConfig
	tunnel := startFixtureTunnel(t, context.Background(), o, dial, testHandlerOrigin(handler))
	var got observedResponse
	select {
	case got = <-result:
	case <-time.After(3 * time.Second):
		t.Fatal("response did not terminate")
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	return got
}

// This independent reference bypasses the tunnel and uses ordinary net/http
// semantics over a private handler pipe, including HEAD and bodyless statuses.
func directHandlerResponse(t *testing.T, method string, handler http.Handler) (*http.Response, string) {
	t.Helper()
	origin := testHandlerOrigin(handler)
	origin.start(context.Background())
	defer origin.close()
	transport := &http.Transport{DialContext: origin.dial}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequest(method, "http://sdk-handler.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, string(body)
}

func fidelityCookieHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("X-Repeat", "one,two")
	w.Header().Add("X-Repeat", "three")
	http.SetCookie(w, &http.Cookie{Name: "first", Value: "one,fragment=two", Path: "/", Expires: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)})
	http.SetCookie(w, &http.Cookie{Name: "second", Value: "three", Path: "/"})
	w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(w, "response bytes")
}

func TestHTTPFidelityLegacyHeaderLoss(t *testing.T) {
	handler := http.HandlerFunc(fidelityCookieHandler)
	reference, body := directHandlerResponse(t, http.MethodGet, handler)
	if len(reference.Header.Values("X-Repeat")) != 2 || len(reference.Cookies()) != 2 {
		t.Fatal("reference lacks repeated fields")
	}
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			got := observeResponse(t, mode, http.MethodGet, handler)
			if got.status != reference.StatusCode || got.body != body {
				t.Fatalf("status/body: %d %q", got.status, got.body)
			}
			if got.headers["X-Repeat"] != strings.Join(reference.Header.Values("X-Repeat"), ", ") || got.headers["Set-Cookie"] != strings.Join(reference.Header.Values("Set-Cookie"), ", ") {
				t.Fatalf("legacy map: %v", got.headers)
			}
			t.Logf("legacy map collapses 2/2 repeated fields into one value each; body=%d bytes", len(got.body))
		})
	}
}
