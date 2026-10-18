package host

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed templates/assets/*
var webAssets embed.FS

// webAssetURL changes whenever the embedded bytes change, keeping cached scripts
// paired with their page across upgrades and rollbacks.
func webAssetURL(name string) (string, error) {
	body, err := webAssets.ReadFile("templates/assets/" + name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("/assets/%s?v=%x", name, sha256.Sum256(body)), nil
}

func serveWebAsset(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/favicon.ico" && !strings.HasPrefix(r.URL.Path, "/assets/") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", 405)
		return true
	}
	name := strings.TrimPrefix(r.URL.Path, "/assets/")
	if r.URL.Path == "/favicon.ico" {
		name = "favicon.ico"
	}
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
	if name == "site.webmanifest" {
		// Tunnel error pages link this public manifest on the platform origin.
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
