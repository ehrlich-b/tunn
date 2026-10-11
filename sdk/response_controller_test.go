package tunn

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/testutil/httpconformance"
)

func TestHTTPFidelityControllerWrapper(t *testing.T) {
	for _, mode := range []string{"buffered", "streaming"} {
		t.Run(mode, func(t *testing.T) {
			report := make(chan error, 1)
			got := observeResponse(t, mode, "GET", httpconformance.ControllerHandler(report))
			if err := <-report; err != nil {
				t.Fatal(err)
			}
			if got.status != 202 || got.body != "abc" {
				t.Fatalf("controller response=%d %q", got.status, got.body)
			}
		})
	}
}

func TestHTTPFidelityReadDeadline(t *testing.T) {
	type result struct {
		body string
		err  error
	}
	outcome := make(chan result, 1)
	origin := testHandlerOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(httpconformance.WriterWrapper{ResponseWriter: w})
		if err := controller.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
			outcome <- result{err: err}
			return
		}
		body, err := io.ReadAll(r.Body)
		outcome <- result{string(body), err}
	}))
	origin.start(context.Background())
	defer origin.close()
	conn, err := origin.dial(context.Background(), "tcp", "sdk-handler.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: sdk-handler.invalid\r\nContent-Length: 3\r\n\r\na"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-outcome:
		var timeout net.Error
		if got.body != "a" || !errors.As(got.err, &timeout) || !timeout.Timeout() {
			t.Fatalf("incomplete upload read=%q error=%v", got.body, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read deadline did not interrupt incomplete upload")
	}
}
