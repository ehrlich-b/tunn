package host

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalAppDownClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{&localTargetRejectedError{message: "failed to reach local target"}, true},
		{fmt.Errorf("wrapped: %w", &localTargetRejectedError{message: "failed to reach local TCP target"}), true},
		{&localTargetRejectedError{message: "failed to create local HTTP request"}, false},
		{errors.New("local target rejected connection: failed to reach local target"), false},
		{&ingressLimitError{}, false},
	} {
		if got := localAppUnreachable(tc.err); got != tc.want {
			t.Errorf("%v: got %v", tc.err, got)
		}
	}
	if (&localTargetRejectedError{message: "x"}).Error() != "local target rejected connection: x" {
		t.Fatal("error text changed")
	}
}

func TestLocalAppDownPage(t *testing.T) {
	p := &ProxyServer{Domain: "tunn.to"}
	r := httptest.NewRequest("GET", "https://k7m2.tunn.to/checkout?token=QUERY_SENTINEL", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	if !acceptsHTML(r) {
		t.Fatal("browser request not treated as HTML")
	}
	w := httptest.NewRecorder()
	p.writeLocalAppDown(w, r)
	body := w.Body.String()
	if w.Code != 502 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Header())
	}
	for _, want := range []string{"Local app not answering", "k7m2.tunn.to", "GET /checkout", "[x] not answering", "url(https://tunn.to/assets/"} {
		if !strings.Contains(body, want) {
			t.Error("missing", want)
		}
	}
	for _, leak := range []string{"QUERY_SENTINEL", "rejected connection", "target_error", "url(/assets/"} {
		if strings.Contains(body, leak) {
			t.Error("leaked", leak)
		}
	}
	for _, accept := range []string{"", "application/json", "*/*"} {
		r := httptest.NewRequest("GET", "https://k7m2.tunn.to/", nil)
		r.Header.Set("Accept", accept)
		if acceptsHTML(r) {
			t.Error("non-browser request treated as HTML:", accept)
		}
	}
	post := httptest.NewRequest("POST", "https://k7m2.tunn.to/hooks", nil)
	post.Header.Set("Accept", "text/html")
	if acceptsHTML(post) {
		t.Error("POST must keep the plain 502")
	}
}
