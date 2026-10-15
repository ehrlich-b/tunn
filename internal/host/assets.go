package host

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed templates/assets/*
var webAssets embed.FS

func serveWebAsset(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/assets/") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", 405)
		return true
	}
	name := strings.TrimPrefix(r.URL.Path, "/assets/")
	if !fs.ValidPath(name) {
		http.NotFound(w, r)
		return true
	}
	body, err := webAssets.ReadFile("templates/assets/" + name)
	if err != nil {
		http.NotFound(w, r)
		return true
	}
	contentType := mime.TypeByExtension(path.Ext(name))
	if path.Ext(name) == ".woff2" {
		contentType = "font/woff2"
		// Error pages on tunnel hosts load the shared fonts cross-origin.
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}
