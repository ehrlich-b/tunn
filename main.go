// main.go
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"os"
	"strings"

	"github.com/aojea/h2rev2"
	"golang.org/x/net/http2"
)

/* ---------------- shared flags ---------------- */

var (
	mode  = flag.String("mode", "client", "host | client")
	to    = flag.String("to", "http://127.0.0.1:8000", "URL to forward to")
	id    = flag.String("id", "", "tunnel ID (client); blank → random")
	dom   = flag.String("domain", "tunn.to", "public apex domain")
	token string
)

/* ---------------- host logic ---------------- */

func runHost() {
	/* ---- TLS ---- */

	certFile := "/app/certs/fullchain.pem" // baked into the image
	keyFile := "/app/certs/privkey.pem"

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("loading cert: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	/* ---- reverse-dial plumbing ---- */

	// Create a reverse connection pool for both connections and proxying
	revPool := h2rev2.NewReversePool()
	defer revPool.Close()

	mux := http.NewServeMux()

	// /announce endpoint - this is where clients establish reverse connections
	mux.Handle("/revdial", auth(func(w http.ResponseWriter, r *http.Request) {
		// Let the reverse pool handle the connection
		revPool.ServeHTTP(w, r)

		// Get the client ID from the URL query parameter
		clientID := r.URL.Query().Get("id")
		log.Printf("client %s announced", clientID)
	}))

	// catch-all proxy for *.tunn.to
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sub := strings.Split(r.Host, ".")[0] // <id> from <id>.tunn.to
		if sub == *dom || sub == "www" {
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
	log.Print("host ready on :443")
	log.Fatal(srv.ListenAndServeTLS("", "")) // cert/key via TLSConfig
}

func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		receivedAuth := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + token

		log.Printf("auth: checking token for %s", r.RemoteAddr)
		log.Printf("auth: received token: '%s'", receivedAuth)
		log.Printf("auth: expected token: '%s'", expectedAuth)

		if receivedAuth != expectedAuth {
			log.Printf("auth: INVALID TOKEN for %s - '%s' != '%s'", r.RemoteAddr, receivedAuth, expectedAuth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		log.Printf("auth: valid token for %s", r.RemoteAddr)
		next(w, r)
	}
}

/* ---------------- client logic ---------------- */

func runClient() {
	if *id == "" {
		*id = randID(7)
	}
	log.Printf("client: starting with id %s", *id)

	// Create an HTTP client with HTTP/2 support
	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Note: In production, use proper certificate validation
			},
		},
	}

	// Add authorization header to requests
	baseURL := "https://" + *dom
	log.Printf("client: announcing to %s", baseURL)

	// Create a request interceptor to add Authorization header
	originalTransport := client.Transport
	client.Transport = &authTransport{
		transport: originalTransport,
		token:     token,
	}

	// Create the listener with proper URL
	ln, err := h2rev2.NewListener(client, baseURL, *id)
	if err != nil {
		log.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	pubURL := fmt.Sprintf("https://%s.%s", *id, *dom)

	upstream, err := neturl.Parse(*to)
	if err != nil {
		log.Fatalf("invalid upstream URL %q: %v", *to, err)
	}
	log.Printf("🔗 %s → %s", pubURL, upstream.Host)
	prefix := "/proxy/" + *id + "/"
	proxy := &httputil.ReverseProxy{
		FlushInterval: -1,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//InsecureSkipVerify: true, // Make this configurable
			},
		},
		Director: func(req *http.Request) {
			// point at the local server
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host

			// strip the /proxy/<id>/ prefix
			if strings.HasPrefix(req.URL.Path, prefix) {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, prefix)
			}
			if !strings.HasPrefix(req.URL.Path, "/") {
				req.URL.Path = "/" + req.URL.Path
			}

			// make the Host header match the upstream (optional but polite)
			req.Host = req.URL.Host
		},
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// context.Canceled is a common error when the client closes the connection
		// before the response is fully written. It's not a server-side error.
		if err == context.Canceled {
			log.Printf("client: request canceled by remote: %s", r.RemoteAddr)
			return
		}
		log.Printf("client: reverse proxy error for request %s to %s: %v", r.URL.String(), upstream.String(), err)
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}

	srv := &http.Server{
		Handler: proxy,
	}

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("proxy server error: %v", err)
	}
}

func randID(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

/* ---------------- entrypoint ---------------- */

func main() {
	flag.Parse()

	envToken := os.Getenv("TOKEN")
	if envToken != "" {
		token = envToken
		log.Printf("Using token from TOKEN environment variable")
	} else {
		log.Fatal("Please set the TOKEN environment variable")
	}

	switch *mode {
	case "host":
		runHost()
	case "client":
		runClient()
	default:
		runClient()
	}
}

// authTransport adds an Authorization header to requests
type authTransport struct {
	transport http.RoundTripper
	token     string
}

// RoundTrip implements the http.RoundTripper interface
func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	log.Printf("client: sending request to %s with token: '%s'", req.URL, t.token)
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		log.Printf("client: request to %s failed: %v", req.URL, err)
	} else {
		log.Printf("client: response from %s: %s", req.URL, resp.Status)
		if resp.StatusCode == http.StatusUnauthorized {
			log.Printf("client: AUTH FAILURE - token '%s' was rejected", t.token)
		}
	}
	return resp, err
}
