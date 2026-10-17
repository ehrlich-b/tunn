package host

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"time"

	statuspage "github.com/ehrlich-b/tunn/internal/status"
)

//go:embed templates/status-docs.html
var statusDocsHTML string

//go:embed templates/docker-docs.html
var dockerDocsHTML string

func (p *ProxyServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	statuspage.Headers(w)
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Invalid status host", 403)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", 405)
		return
	}
	unknown := func() { statuspage.RenderWithHead(w, r, statuspage.Unknown(time.Now().UTC()), 503, iconHead) }
	if p.config.StatusURL == "" {
		unknown()
		return
	}
	origin, err := statuspage.Origin(p.config.StatusURL)
	if err != nil {
		unknown()
		return
	}
	origin.Path = r.URL.Path
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.String(), nil)
	if err != nil {
		unknown()
		return
	}
	// Do not forward cookies, authorization, query parameters or client headers.
	resp, err := statuspage.ProbeClient(3 * time.Second).Do(req)
	if err != nil {
		unknown()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 503 {
		unknown()
		return
	}
	contentType := "text/html; charset=utf-8"
	if r.URL.Path == "/status.json" {
		contentType = "application/json; charset=utf-8"
	}
	if resp.Header.Get("Content-Type") != contentType {
		unknown()
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		unknown()
		return
	}
	if contentType == "text/html; charset=utf-8" {
		body = []byte(withPageHead(string(body)))
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func serveFeatureDocs(w http.ResponseWriter, r *http.Request, title, content string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	writePageStart(w, title)
	_, _ = fmt.Fprint(w, content)
	writePageEnd(w)
}
