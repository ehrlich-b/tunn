package host

import (
	"net/http"
	"strings"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Reserve the same cookie namespaces in both directions. Parent-domain login
// cookies must never be exposed to or set by a published application.
func isPlatformCookie(name string) bool {
	return strings.HasPrefix(name, "tunn_") || strings.HasPrefix(name, "__Host-tunn_") || strings.HasPrefix(name, "__Secure-tunn_")
}

func copyApplicationResponseHeaders(dst http.Header, src map[string]string) {
	for name, value := range src {
		if strings.HasPrefix(strings.ToLower(name), "tunn-") {
			continue
		}
		if !strings.EqualFold(name, "Set-Cookie") {
			dst.Set(name, value)
			continue
		}
		// The wire protocol joins repeated headers with commas. Split cookie
		// pairs, retaining commas in Expires dates, and emit separate headers.
		for _, value := range splitSetCookies(value) {
			cookie, err := http.ParseSetCookie(value)
			if err == nil && !isPlatformCookie(cookie.Name) {
				dst.Add("Set-Cookie", value)
			}
		}
	}
}

func splitSetCookies(value string) []string {
	var cookies []string
	start := 0
	for i := 0; i < len(value); i++ {
		if value[i] != ',' {
			continue
		}
		rest := strings.TrimSpace(value[i+1:])
		if end := strings.IndexAny(rest, ";,"); end >= 0 {
			rest = rest[:end]
		}
		// A date continuation has no cookie pair. Cookie names and values are
		// validated by the standard parser before anything reaches the browser.
		if _, err := http.ParseSetCookie(rest); err != nil {
			continue
		}
		cookies = append(cookies, strings.TrimSpace(value[start:i]))
		start = i + 1
	}
	return append(cookies, strings.TrimSpace(value[start:]))
}

// A nonempty additive list replaces the entire map. Cookie values in the list
// are already individual fields and must never pass through comma splitting.
func copyApplicationResponseHeaderFields(dst http.Header, legacy map[string]string, fields []*pb.HttpHeader) {
	if len(fields) == 0 {
		copyApplicationResponseHeaders(dst, legacy)
		return
	}
	seen := make(map[string]bool)
	for _, field := range fields {
		if field == nil || strings.HasPrefix(strings.ToLower(field.Name), "tunn-") {
			continue
		}
		name := http.CanonicalHeaderKey(field.Name)
		if strings.EqualFold(name, "Set-Cookie") {
			cookie, err := http.ParseSetCookie(field.Value)
			if err == nil && !isPlatformCookie(cookie.Name) {
				dst.Add("Set-Cookie", field.Value)
			}
			continue
		}
		if !seen[name] {
			dst.Del(name)
			seen[name] = true
		}
		dst.Add(name, field.Value)
	}
}
