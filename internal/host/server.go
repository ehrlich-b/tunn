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
	Domain string
	Token  string
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
	mux.Handle("/revdial", common.HTTPLoggingMiddleware(auth(func(w http.ResponseWriter, r *http.Request) {
		// Let the reverse pool handle the connection
		revPool.ServeHTTP(w, r)

		// Get the client ID from the URL query parameter
		clientID := r.URL.Query().Get("id")
		common.LogInfo("client announced", "id", clientID)
	})))

	// catch-all proxy for *.tunn.to
	mux.Handle("/", common.HTTPLoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.Host, ".")
		sub := parts[0] // <id> from <id>.tunn.to
		
		// Check if this is the apex domain (tunn.to) or www subdomain
		if r.Host == s.Domain || sub == "www" {
			http.Error(w, "no id", 404)
			return
		}

		// Get the dialer for this subdomain
		dialer := revPool.GetDialer(sub)
		if dialer == nil {
			http.Error(w, "tunnel offline", 503)
			return
		}

		// We'll redirect to the proxy endpoint of the ReversePool
		r.URL.Path = "/proxy/" + sub + r.URL.Path

		// Let the ReversePool handle the proxy request
		revPool.ServeHTTP(w, r)
	})))

	return mux
}

// Run starts the host server
func (s *Server) Run() {
	// TLS setup
	certFile := "/app/certs/fullchain.pem" // baked into the image
	keyFile := "/app/certs/privkey.pem"

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
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
