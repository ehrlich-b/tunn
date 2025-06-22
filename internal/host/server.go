package host

import (
	"crypto/tls"
	"log/slog"
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

// Run starts the host server
func (s *Server) Run() {
	// TLS setup
	certFile := "/app/certs/fullchain.pem" // baked into the image
	keyFile := "/app/certs/privkey.pem"

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		slog.Error("loading cert", "error", err)
		os.Exit(1)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	// Create a reverse connection pool for both connections and proxying
	revPool := h2rev2.NewReversePool()
	defer revPool.Close()

	mux := http.NewServeMux()

	// /announce endpoint - this is where clients establish reverse connections
	auth := common.AuthMiddleware(s.Token)
	mux.Handle("/revdial", auth(func(w http.ResponseWriter, r *http.Request) {
		// Let the reverse pool handle the connection
		revPool.ServeHTTP(w, r)

		// Get the client ID from the URL query parameter
		clientID := r.URL.Query().Get("id")
		slog.Info("client announced", "id", clientID)
	}))

	// catch-all proxy for *.tunn.to
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sub := strings.Split(r.Host, ".")[0] // <id> from <id>.tunn.to
		if sub == s.Domain || sub == "www" {
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
	})

	srv := &http.Server{
		Addr:      ":443",
		Handler:   mux,
		TLSConfig: tlsCfg,
	}
	http2.ConfigureServer(srv, &http2.Server{})
	slog.Info("host ready", "port", 443)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}
