package host

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Close interrupts the request but deliberately leaves Read on a separate
// barrier, modeling the interval between net/http cancellation and Read exit.
type joinUploadBody struct {
	reading chan struct{}
	closed  chan struct{}
	release chan struct{}
	stopped chan struct{}
	cancel  context.CancelFunc
	once    sync.Once
}

func (b *joinUploadBody) Read([]byte) (int, error) {
	close(b.reading)
	<-b.release
	close(b.stopped)
	return 0, io.ErrClosedPipe
}

func (b *joinUploadBody) Close() error {
	b.once.Do(func() {
		b.cancel()
		close(b.closed)
	})
	return nil
}

func TestHTTPFidelityUploadReaderJoinedBeforeHandlerReturn(t *testing.T) {
	for _, exit := range []string{"cancellation", "response-complete", "rejection", "disconnect"} {
		t.Run(exit, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &joinUploadBody{
				reading: make(chan struct{}), closed: make(chan struct{}),
				release: make(chan struct{}), stopped: make(chan struct{}), cancel: cancel,
			}
			release := sync.OnceFunc(func() { close(body.release) })
			defer release()
			proxy, tunnel, closes := responseProgressProxy(http.StatusAccepted, "", false)
			opened := make(chan string, 1)
			tunnel.Stream = &securityStream{onSend: func(message *pb.TunnelMessage) error {
				if open := message.GetConnectionOpen(); open != nil {
					opened <- open.ConnectionId
				}
				if message.GetConnectionClose() != nil {
					closes.Add(1)
				}
				return nil
			}}
			request := httptest.NewRequest(http.MethodPost, "http://api.tunn.test/", body).WithContext(ctx)
			request.ContentLength = -1
			returned := make(chan bool, 1)
			go func() {
				http.HandlerFunc(proxy.handleWebProxy).ServeHTTP(httptest.NewRecorder(), request)
				select {
				case <-body.stopped:
					returned <- true
				default:
					returned <- false
				}
			}()
			id := waitResponseSignal(t, opened)
			waitResponseSignal(t, body.reading)
			switch exit {
			case "cancellation":
				cancel()
			case "response-complete", "rejection":
				tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{
					ConnectionId: id, Success: exit == "response-complete", ErrorMessage: "request refused",
					HttpResponse: &pb.HttpResponseHead{StatusCode: http.StatusAccepted},
				}}})
				if exit == "response-complete" {
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id}}})
				}
			case "disconnect":
				tunnel.closePendingConnections()
			}
			waitResponseSignal(t, body.closed)
			// Even though the request is now cancelled, cleanup must wait for
			// the read to stop rather than selecting Context.Done and returning.
			select {
			case <-returned:
				t.Fatal("ServeHTTP returned while upload Read was still blocked")
			case <-time.After(10 * time.Millisecond):
			}
			release()
			if !waitResponseSignal(t, returned) {
				t.Fatal("upload Read had not stopped at ServeHTTP return")
			}
			assertUploadResponseCleanup(t, tunnel, closes)
		})
	}
}

func TestStreamingHTTPUploadJoinIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &joinUploadBody{
		reading: make(chan struct{}), closed: make(chan struct{}),
		release: make(chan struct{}), stopped: make(chan struct{}), cancel: cancel,
	}
	defer func() { close(body.release); waitResponseSignal(t, body.stopped) }()
	proxy, tunnel, _ := responseProgressProxy(http.StatusAccepted, "", false)
	request := httptest.NewRequest(http.MethodPost, "http://api.tunn.test/", body).WithContext(ctx)
	returned := make(chan error, 1)
	go func() { returned <- proxy.proxyStreamingHTTPOverGRPC(httptest.NewRecorder(), request, tunnel) }()
	waitResponseSignal(t, body.reading)
	cancel()
	if err := waitResponseSignal(t, returned); !errors.Is(err, context.Canceled) {
		t.Fatalf("request error = %v, want cancellation", err)
	}
	select {
	case <-body.stopped:
		t.Fatal("fixture released Read before testing the join bound")
	default:
	}
}

type joinSendBody struct {
	io.Reader
	reads atomic.Int32
}

func (b *joinSendBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return b.Reader.Read(p)
}

func (b *joinSendBody) Close() error { return nil }

func TestHTTPFidelityUploadCancelledSendExits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release, sent := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	tunnel := &TunnelConnection{Stream: &securityStream{onSend: func(message *pb.TunnelMessage) error {
		calls.Add(1)
		if message.GetConnectionData() == nil {
			return errors.New("unexpected non-data upload message")
		}
		close(started)
		<-release
		close(sent)
		return nil
	}}}
	defer func() { close(release); waitResponseSignal(t, sent) }()
	body := &joinSendBody{Reader: strings.NewReader("upload")}
	var count atomic.Int64
	type result struct {
		bytes int64
		err   error
	}
	done := make(chan result, 1)
	go func() {
		n, err := streamConnectionInputContext(ctx, body, tunnel, "request", &count, MaxBodySize)
		done <- result{n, err}
	}()
	waitResponseSignal(t, started)
	cancel()
	got := waitResponseSignal(t, done)
	if !errors.Is(got.err, context.Canceled) || !strings.Contains(got.err.Error(), "failed to stream HTTP request body") {
		t.Fatalf("upload error = %v, want cancelled data send", got.err)
	}
	if got.bytes != 6 || count.Load() != 6 || body.reads.Load() != 1 || calls.Load() != 1 {
		t.Fatalf("upload continued after cancelled send: bytes=%d count=%d reads=%d sends=%d", got.bytes, count.Load(), body.reads.Load(), calls.Load())
	}
}
