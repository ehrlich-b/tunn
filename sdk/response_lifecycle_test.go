package tunn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type responseTrace struct {
	observedResponse
	metadata, terminals int
	ended               bool
}

func responseFrameID(message *pb.TunnelMessage) string {
	switch {
	case message.GetHttpResponse() != nil:
		return message.GetHttpResponse().ConnectionId
	case message.GetConnectionAccept() != nil:
		return message.GetConnectionAccept().ConnectionId
	case message.GetConnectionData() != nil:
		return message.GetConnectionData().ConnectionId
	case message.GetConnectionHalfClose() != nil:
		return message.GetConnectionHalfClose().ConnectionId
	case message.GetConnectionClose() != nil:
		return message.GetConnectionClose().ConnectionId
	default:
		return ""
	}
}

// Used by reconnect and late-terminal fixtures. It accounts for a single
// request, including metadata-before-bytes and exactly one terminal result.
func (r *responseTrace) consume(message *pb.TunnelMessage) error {
	if r.ended {
		return errors.New("response frame after terminal result")
	}
	r.frames = append(r.frames, message)
	switch {
	case message.GetHttpResponse() != nil:
		response := message.GetHttpResponse()
		r.status, r.headers, r.fields, r.body = int(response.StatusCode), response.Headers, response.HeaderFields, string(response.Body)
		r.trailerNames, r.trailers = response.TrailerNames, response.Trailers
		r.metadata++
		r.terminals++
		r.ended = true
	case message.GetConnectionAccept() != nil:
		accept := message.GetConnectionAccept()
		if !accept.Success {
			r.rejection = accept.ErrorMessage
			r.terminals++
			r.ended = true
			return nil
		}
		if accept.HttpResponse == nil {
			return errors.New("accepted HTTP request without metadata")
		}
		head := accept.HttpResponse
		r.status, r.headers, r.fields, r.trailerNames = int(head.StatusCode), head.Headers, head.HeaderFields, head.TrailerNames
		r.metadata++
	case message.GetConnectionData() != nil:
		if r.metadata != 1 {
			return errors.New("body bytes before one final metadata frame")
		}
		r.body += string(message.GetConnectionData().Data)
	case message.GetConnectionHalfClose() != nil:
		if r.metadata != 1 {
			return errors.New("successful EOF before final metadata")
		}
		r.trailers = message.GetConnectionHalfClose().Trailers
		r.terminals++
		r.ended = true
	case message.GetConnectionClose() != nil:
		r.terminals++
		r.ended = true
	}
	if r.metadata > 1 || r.terminals > 1 {
		return errors.New("duplicate metadata or terminal result")
	}
	return nil
}

func sendFixtureRequest(stream pb.TunnelService_EstablishTunnelServer, mode, id, path string) error {
	if mode == "buffered" {
		return stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: id, Method: "GET", Path: path}}})
	}
	if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: &pb.ConnectionOpen{ConnectionId: id, Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: path}}}}); err != nil {
		return err
	}
	return stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id}}})
}

func receiveResponseGroup(stream pb.TunnelService_EstablishTunnelServer, traces map[string]*responseTrace) error {
	remaining := len(traces)
	for remaining > 0 {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		id := responseFrameID(message)
		if id == "" {
			continue
		}
		trace, ok := traces[id]
		if !ok {
			return fmt.Errorf("response for another generation/request: %s", id)
		}
		if err = trace.consume(message); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		if trace.ended {
			remaining--
		}
	}
	return nil
}

func TestHTTPFidelityReconnectNegotiation(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			// First connect, supported reconnect, legacy reconnect, restoration.
			var generation atomic.Int32
			result := make(chan error, 1)
			started := make(chan string, 8)
			gates := make(map[string]chan struct{})
			for g := 1; g <= 4; g++ {
				for _, id := range []string{"left", "right"} {
					gates[fmt.Sprintf("/g%d/%s", g, id)] = make(chan struct{})
				}
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Trailer", "X-End")
				w.Header().Add("Set-Cookie", "first=one; Path=/")
				w.Header().Add("Set-Cookie", "second=two; Path=/")
				w.WriteHeader(202)
				_, _ = io.WriteString(w, r.URL.Path)
				w.(http.Flusher).Flush()
				started <- r.URL.Path
				select {
				case <-gates[r.URL.Path]:
					w.Header().Set("X-End", r.URL.Path)
				case <-r.Context().Done():
				}
			})
			dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) (err error) {
				g := generation.Add(1)
				defer func() {
					if err != nil && status.Code(err) != codes.Unavailable {
						select {
						case result <- err:
						default:
						}
					}
				}()
				if g > 4 {
					return errors.New("unexpected extra reconnect")
				}
				reg, err := registration(stream)
				if err != nil {
					return err
				}
				caps := []string{common.CapabilityHTTPStreamV1, common.CapabilityConnectionStreamV1, common.CapabilityWebSocketV1}
				if g != 3 {
					caps = append(caps, common.CapabilityHTTPResponseTrailersV1)
				}
				if err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://" + reg.TunnelId + ".sdk.test", Capabilities: caps}}}); err != nil {
					return err
				}
				traces := map[string]*responseTrace{"left": {}, "right": {}}
				for id := range traces {
					if err = sendFixtureRequest(stream, mode, id, fmt.Sprintf("/g%d/%s", g, id)); err != nil {
						return err
					}
				}
				seen := map[string]bool{}
				for len(seen) < 2 {
					select {
					case path := <-started:
						if !strings.HasPrefix(path, fmt.Sprintf("/g%d/", g)) || seen[path] {
							return fmt.Errorf("handler crossed generation barrier: %s", path)
						}
						seen[path] = true
					case <-stream.Context().Done():
						return stream.Context().Err()
					}
				}
				for path := range seen {
					close(gates[path])
				}
				if err = receiveResponseGroup(stream, traces); err != nil {
					return err
				}
				for id, trace := range traces {
					if trace.terminals != 1 {
						return fmt.Errorf("g%d/%s terminal count=%d", g, id, trace.terminals)
					}
					if g == 3 {
						if mode == "buffered" {
							if trace.status != 502 || !strings.Contains(trace.body, "upgraded relay") {
								return fmt.Errorf("legacy buffered response used stale capability: %+v", trace)
							}
						} else if !strings.Contains(trace.rejection, "upgraded relay") || trace.body != "" {
							return fmt.Errorf("legacy streaming response used stale capability: %+v", trace)
						}
					} else {
						path := fmt.Sprintf("/g%d/%s", g, id)
						if trace.status != 202 || trace.metadata != 1 || trace.body != path || !reflect.DeepEqual(trace.trailerNames, []string{"X-End"}) || len(trace.trailers) != 1 || trace.trailers[0].Value != path || len(common.DecodeHTTPResponseHeaders(trace.headers, trace.fields).Values("Set-Cookie")) != 2 {
							return fmt.Errorf("g%d/%s response attribution/fidelity: %+v", g, id, trace)
						}
					}
				}
				if g < 4 {
					return status.Error(codes.Unavailable, "finite reconnect fixture")
				}
				result <- nil
				return drainUntilCanceled(stream)
			})
			o := fixtureOptions()
			o.TLSConfig = tlsConfig
			o.Origin = "http://sdk-handler.invalid"
			o.Reconnect = &ReconnectPolicy{MaxAttempts: 4, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}
			tunnel := startFixtureTunnel(t, context.Background(), o, dial, testHandlerOrigin(handler))
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("finite reconnect schedules did not complete")
			}
			if err := tunnel.Close(); err != nil {
				t.Fatal(err)
			}
			if generation.Load() != 4 {
				t.Fatalf("generations=%d", generation.Load())
			}
			t.Log("8/8 request outcomes: 6 exact cookie/body/trailer successes; 2 explicit legacy-capability rejections")
		})
	}
}

func TestHTTPFidelityRequestsSpanReconnect(t *testing.T) {
	var generation atomic.Int32
	result := make(chan error, 1)
	canceled := make(chan string, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Trailer", "X-End")
		w.Header().Add("Set-Cookie", "request="+strings.ReplaceAll(r.URL.Path, "/", "_")+"; Path=/")
		w.WriteHeader(202)
		_, _ = io.WriteString(w, r.URL.Path)
		w.(http.Flusher).Flush()
		if strings.HasPrefix(r.URL.Path, "/g1/") {
			<-r.Context().Done()
			canceled <- r.URL.Path
			return
		}
		w.Header().Set("X-End", r.URL.Path)
	})
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) (err error) {
		g := generation.Add(1)
		defer func() {
			if err != nil && status.Code(err) != codes.Unavailable {
				select {
				case result <- err:
				default:
				}
			}
		}()
		if g > 2 {
			return errors.New("unexpected reconnect")
		}
		reg, err := registration(stream)
		if err != nil {
			return err
		}
		if err = acceptRegistration(stream, reg); err != nil {
			return err
		}
		traces := map[string]*responseTrace{"left": {}, "right": {}}
		for id := range traces {
			if err = sendFixtureRequest(stream, "streaming", id, fmt.Sprintf("/g%d/%s", g, id)); err != nil {
				return err
			}
		}
		if g == 1 {
			// Both prefixes must be received before the relay drops generation 1.
			for traces["left"].body == "" || traces["right"].body == "" {
				message, err := stream.Recv()
				if err != nil {
					return err
				}
				id := responseFrameID(message)
				if id == "" {
					continue
				}
				trace := traces[id]
				if trace == nil {
					return fmt.Errorf("foreign request %s", id)
				}
				if err = trace.consume(message); err != nil {
					return err
				}
				if trace.ended {
					return errors.New("unfinished response unexpectedly completed before disconnect")
				}
			}
			for id, trace := range traces {
				if trace.body != "/g1/"+id || trace.metadata != 1 || trace.terminals != 0 {
					return fmt.Errorf("bad interrupted response %+v", trace)
				}
			}
			return status.Error(codes.Unavailable, "disconnect after both prefixes")
		}
		if err = receiveResponseGroup(stream, traces); err != nil {
			return err
		}
		for id, trace := range traces {
			if trace.status != 202 || trace.body != "/g2/"+id || trace.terminals != 1 || len(trace.trailers) != 1 || trace.trailers[0].Value != "/g2/"+id {
				return fmt.Errorf("reused request ID crossed connection generations: %+v", trace)
			}
		}
		result <- nil
		return drainUntilCanceled(stream)
	})
	o := fixtureOptions()
	o.TLSConfig = tlsConfig
	o.Origin = "http://sdk-handler.invalid"
	o.Reconnect = &ReconnectPolicy{MaxAttempts: 2, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}
	tunnel := startFixtureTunnel(t, context.Background(), o, dial, testHandlerOrigin(handler))
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect did not finish")
	}
	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case path := <-canceled:
			if seen[path] {
				t.Fatal("duplicate request cancellation")
			}
			seen[path] = true
		case <-time.After(time.Second):
			t.Fatal("old-generation handlers were retained")
		}
	}
	if !seen["/g1/left"] || !seen["/g1/right"] {
		t.Fatal(seen)
	}
	var closers sync.WaitGroup
	for i := 0; i < 2; i++ {
		closers.Add(1)
		go func() {
			defer closers.Done()
			if err := tunnel.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	closers.Wait()
	collectEvents(t, tunnel)
	t.Log("4/4 outcomes: 2 interrupted prefixes in generation 1; 2 successful reused IDs in generation 2; 2/2 old handlers canceled")
}

func TestHTTPFidelityCompletedBodyLateTerminal(t *testing.T) {
	for _, schedule := range []string{"late-upload-half-close", "late-upload-error-close", "lifetime-cancel"} {
		t.Run(schedule, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				trace *responseTrace
				err   error
			}
			completed := make(chan result, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Set-Cookie", "first=one; Path=/")
				w.Header().Add("Set-Cookie", "second=two; Path=/")
				w.Header().Add("Trailer", "X-End")
				w.WriteHeader(202)
				_, _ = io.WriteString(w, r.URL.Path)
				w.(http.Flusher).Flush()
				w.Header().Set("X-End", r.URL.Path)
			})
			dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) (err error) {
				defer func() {
					if err != nil {
						select {
						case completed <- result{err: err}:
						default:
						}
					}
				}()
				reg, err := registration(stream)
				if err != nil {
					return err
				}
				if err = acceptRegistration(stream, reg); err != nil {
					return err
				}
				if err = sendFixtureRequest(stream, "streaming", "complete", "/complete"); err != nil {
					return err
				}
				traces := map[string]*responseTrace{"complete": {}}
				if err = receiveResponseGroup(stream, traces); err != nil {
					return err
				}
				trace := traces["complete"]
				if trace.status != 202 || trace.body != "/complete" || trace.metadata != 1 || trace.terminals != 1 || len(trace.trailers) != 1 || trace.trailers[0].Value != "/complete" || len(common.DecodeHTTPResponseHeaders(trace.headers, trace.fields).Values("Set-Cookie")) != 2 {
					return fmt.Errorf("completed response=%+v", trace)
				}
				if schedule == "lifetime-cancel" {
					completed <- result{trace: trace}
					return drainUntilCanceled(stream)
				}
				if schedule == "late-upload-half-close" {
					err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: "complete"}}})
				} else {
					err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{ConnectionClose: &pb.ConnectionClose{ConnectionId: "complete", ErrorMessage: "late upload failure"}}})
				}
				if err != nil {
					return err
				}
				if err = sendFixtureRequest(stream, "streaming", "fence", "/fence"); err != nil {
					return err
				}
				fence := map[string]*responseTrace{"fence": {}}
				// Any duplicated completion of the previous request now fails as
				// a foreign ID while this deterministic fence is being collected.
				if err = receiveResponseGroup(stream, fence); err != nil {
					return err
				}
				if fence["fence"].body != "/fence" || fence["fence"].terminals != 1 || len(fence["fence"].trailers) != 1 || fence["fence"].trailers[0].Value != "/fence" {
					return errors.New("late terminal contaminated following request")
				}
				completed <- result{trace: trace}
				return drainUntilCanceled(stream)
			})
			o := fixtureOptions()
			o.TLSConfig = tlsConfig
			o.Origin = "http://sdk-handler.invalid"
			tunnel := startFixtureTunnel(t, ctx, o, dial, testHandlerOrigin(handler))
			var got result
			select {
			case got = <-completed:
				if got.err != nil {
					t.Fatal(got.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("late-terminal fixture did not complete")
			}
			if schedule == "lifetime-cancel" {
				cancel()
				waitDone(t, tunnel)
				if !errors.Is(tunnel.Wait(), context.Canceled) {
					t.Fatalf("cancel result=%v", tunnel.Wait())
				}
			} else if err := tunnel.Close(); err != nil {
				t.Fatal(err)
			}
			collectEvents(t, tunnel)
			if got.trace.terminals != 1 || got.trace.body != "/complete" || got.trace.trailers[0].Value != "/complete" {
				t.Fatal("completed result changed during finalization")
			}
		})
	}
}
