package tunn

import (
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/testutil/httpconformance"
)

func TestHTTPFidelitySDKContentLengths(t *testing.T) {
	for _, fixture := range []struct{ name, body, length string }{{"exact", "abc", "3"}, {"short", "ab", "3"}, {"long", "abcd", "3"}, {"absent", "abc", ""}} {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if fixture.length != "" {
				w.Header().Set("Content-Length", fixture.length)
			}
			w.WriteHeader(202)
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, fixture.body)
		})
		reference, body, readErr := directHandlerResult(t, "GET", handler)
		mismatch := fixture.name == "short" || fixture.name == "long"
		if mismatch != errors.Is(readErr, io.ErrUnexpectedEOF) {
			t.Fatalf("independent %s response: %q %v", fixture.name, body, readErr)
		}
		for _, mode := range []string{"buffered", "streaming"} {
			t.Run(fixture.name+"/"+mode, func(t *testing.T) {
				got := observeResponse(t, mode, "GET", handler)
				trace := &responseTrace{}
				for _, frame := range got.frames {
					if err := trace.consume(frame); err != nil {
						t.Fatal(err)
					}
				}
				if trace.terminals != 1 {
					t.Fatalf("terminal count=%d", trace.terminals)
				}
				if mismatch && mode == "buffered" {
					if got.status != 502 {
						t.Fatalf("buffered incomplete body became status %d", got.status)
					}
					return
				}
				if mismatch {
					terminal := got.frames[len(got.frames)-1].GetConnectionClose()
					if terminal == nil || terminal.ErrorMessage == "" || got.status != 202 || got.body != body {
						t.Fatalf("streaming mismatch status/body/terminal=%d %q %v, reference=%q %v", got.status, got.body, terminal, body, readErr)
					}
					return
				}
				httpconformance.Assert(t, observation(got), httpconformance.Observation{Status: reference.StatusCode, Header: reference.Header, Trailer: reference.Trailer, Body: body, Terminals: 1})
				if common.DecodeHTTPResponseHeaders(got.headers, got.fields).Get("Content-Length") != fixture.length {
					t.Fatal("SDK changed explicit/absent Content-Length")
				}
			})
		}
	}
}
