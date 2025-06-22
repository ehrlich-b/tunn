package host

import (
	"crypto/tls"
	"net/http"
	"os"
	"strings"

	"github.com/aojea/h2rev2"
	"golang.org/x/net/http2"

	"github.com/ehrlich-b/tunn/internal/common"
)

// Server represents the host server
type Server struct {
	Domain   string
	Token    string
	CertFile string
	KeyFile  string
}

// ReversePoolInterface defines the interface for reverse proxy pools
type ReversePoolInterface interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	GetDialer(id string) *h2rev2.Dialer
}

// CreateHandler creates the HTTP handler for the server
func (s *Server) CreateHandler(revPool ReversePoolInterface) http.Handler {
	mux := http.NewServeMux()

	// /announce endpoint - this is where clients establish reverse connections
	auth := common.AuthMiddleware(s.Token)
	mux.Handle("/revdial", auth(func(w http.ResponseWriter, r *http.Request) {
		clientID := r.URL.Query().Get("id")
		if clientID == "" {
			http.Error(w, "missing client id", 400)
			return
		}

		// Let the reverse pool handle the connection
		revPool.ServeHTTP(w, r)
		common.LogInfo("client announced", "id", clientID)
	}))

	// catch-all proxy for *.tunn.to
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is the apex domain first
		if r.Host == s.Domain {
			http.Error(w, "no id", 404)
			return
		}

		parts := strings.Split(r.Host, ".")
		if len(parts) == 0 {
			http.Error(w, "invalid host", 400)
			return
		}

		sub := parts[0]
		if sub == "www" {
			http.Error(w, "no id", 404)
			return
		}

		// Get the dialer for this subdomain
		dialer := revPool.GetDialer(sub)
		if dialer == nil {
			http.Error(w, "tunnel offline", 503)
			return
		}

		// Rewrite the path for the proxy endpoint
		// Store original path for the client to handle
		originalPath := r.URL.Path
		r.URL.Path = "/proxy/" + sub + "/" + strings.TrimPrefix(originalPath, "/")

		// Let the ReversePool handle the proxy request
		revPool.ServeHTTP(w, r)
	}))

	return mux
}

// Run starts the host server
func (s *Server) Run() {
	cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		common.LogError("loading cert", "error", err)
		os.Exit(1)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	// Create a reverse connection pool for both connections and proxying
	revPool := h2rev2.NewReversePool()
	defer revPool.Close()

	handler := s.CreateHandler(revPool)

	srv := &http.Server{
		Addr:      ":443",
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
	http2.ConfigureServer(srv, &http2.Server{})
	common.LogInfo("host ready", "port", 443)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		common.LogError("server failed", "error", err)
		os.Exit(1)
	}
}
