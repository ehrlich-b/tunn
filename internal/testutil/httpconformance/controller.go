package httpconformance

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// WriterWrapper intentionally forwards only ResponseWriter and Unwrap; the
// controller must discover Flush and deadlines through the wrapped writer.
type WriterWrapper struct{ http.ResponseWriter }

func (w WriterWrapper) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func ControllerHandler(report chan<- error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			report <- fmt.Errorf("handler writer lacks Flusher")
			return
		}
		if _, ok := w.(http.Hijacker); !ok {
			report <- fmt.Errorf("handler writer lacks Hijacker")
			return
		}
		if _, ok := w.(http.Pusher); ok {
			report <- fmt.Errorf("HTTP/1 handler pipe unexpectedly implements HTTP/2 Pusher")
			return
		}
		wrapped := WriterWrapper{w}
		controller := http.NewResponseController(wrapped)
		for _, operation := range []func() error{
			controller.EnableFullDuplex,
			func() error { return controller.SetReadDeadline(time.Now().Add(2 * time.Second)) },
			func() error { return controller.SetWriteDeadline(time.Now().Add(2 * time.Second)) },
			func() error { return controller.SetReadDeadline(time.Time{}) },
			func() error { return controller.SetWriteDeadline(time.Time{}) },
		} {
			if err := operation(); err != nil {
				report <- err
				return
			}
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(wrapped, "abc")
		report <- controller.Flush()
	})
}
