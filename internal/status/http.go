package status

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"time"
)

//go:embed page.html
var pageHTML string
var pageTemplate = template.Must(template.New("status").Parse(pageHTML))

func Headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
}
func Render(w http.ResponseWriter, r *http.Request, v Snapshot, code int) {
	Headers(w)
	var b bytes.Buffer
	if r.URL.Path == "/status.json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(&b).Encode(v)
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := pageTemplate.Execute(&b, v); err != nil {
			http.Error(w, "Status unavailable", 503)
			return
		}
	}
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		_, _ = w.Write(b.Bytes())
	}
}
func Handler(s *Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Headers(w)
		if r.URL.Path != "/status" && r.URL.Path != "/status.json" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", 405)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		now := time.Now().UTC()
		v, err := s.Snapshot(ctx, now)
		code := 200
		if err != nil {
			v = Unknown(now)
			code = 503
		}
		Render(w, r, v, code)
	})
}
