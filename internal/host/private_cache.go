package host

import (
	"bufio"
	"net"
	"net/http"
	"strings"
)

// Application headers cannot override the relay's revocation policy. Apply it
// at commitment so successes, redirects, errors, 304s and streaming heads agree.
func privateResponseHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	for _, name := range []string{"Expires", "Surrogate-Control", "CDN-Cache-Control", "Cloudflare-CDN-Cache-Control"} {
		h.Del(name)
	}
	vary := strings.Join(h.Values("Vary"), ",")
	for _, name := range []string{"Cookie", "Authorization", "Tunn-Authorization"} {
		found := false
		for _, field := range strings.Split(vary, ",") {
			if strings.EqualFold(strings.TrimSpace(field), name) || strings.TrimSpace(field) == "*" {
				found = true
			}
		}
		if !found {
			h.Add("Vary", name)
		}
	}
}

type privateResponseWriter struct {
	http.ResponseWriter
	committed bool
}

func protectResponse(w http.ResponseWriter) http.ResponseWriter {
	if _, ok := w.(*privateResponseWriter); ok {
		return w
	}
	privateResponseHeaders(w.Header())
	return &privateResponseWriter{ResponseWriter: w}
}
func (w *privateResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *privateResponseWriter) WriteHeader(status int) {
	if !w.committed {
		privateResponseHeaders(w.Header())
	}
	if status >= 200 || status == http.StatusSwitchingProtocols {
		w.committed = true
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *privateResponseWriter) Write(body []byte) (int, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}
func (w *privateResponseWriter) Flush() {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *privateResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	privateResponseHeaders(w.Header())
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (p *ProxyServer) protectedResponse(r *http.Request) bool {
	if p.customerHost(r.Host) || extractTunnelID(requestHostname(r.Host), p.Domain) != "" {
		return true
	}
	if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Tunn-Authorization") != "" {
		return true
	}
	for _, prefix := range []string{"/auth/", "/account", "/api/", "/oauth/"} {
		if strings.HasPrefix(r.URL.Path, prefix) {
			return true
		}
	}
	return r.URL.Path == "/login" || r.URL.Path == "/upgrade"
}
