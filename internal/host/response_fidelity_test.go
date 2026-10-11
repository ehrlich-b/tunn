package host

import (
	"net/http"
	"testing"
)

func TestHTTPFidelityLegacyCookieAmbiguity(t *testing.T) {
	// This is a valid cookie value containing a comma and an equals sign. The
	// historical split heuristic mistakes part of it for a third cookie.
	dst := make(http.Header)
	copyApplicationResponseHeaders(dst, map[string]string{"Set-Cookie": "first=one,fragment=two; Path=/, second=three; Path=/"})
	if len(dst.Values("Set-Cookie")) != 3 {
		t.Fatalf("legacy fallback changed: %v", dst)
	}
	t.Log("old wire fallback emits 3 cookie fields for 2 original cookies; exact recovery is impossible")
}
