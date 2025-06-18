// main.go
package main

import (
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"strings"
	"sync"

	"github.com/aojea/h2rev2"
	"golang.org/x/net/http2"
)

/* ---------------- shared flags ---------------- */

var (
	mode  = flag.String("mode", "host", "host | client")
	port  = flag.Int("port", 8080, "local service port (client mode)")
	id    = flag.String("id", "", "tunnel ID (client); blank → random")
	token = flag.String("token", "secret", "shared bearer token")
	dom   = flag.String("domain", "tunn.to", "public apex domain")
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
	mux.Handle("/announce", auth(func(w http.ResponseWriter, r *http.Request) {
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

		// Create the URL path for the proxy
		proxyPath := "/proxy/" + sub + "/"

		// We'll redirect to the proxy endpoint of the ReversePool
		r.URL.Path = proxyPath

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
		if r.Header.Get("Authorization") != "Bearer "+*token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

/* ---------------- client logic ---------------- */

func runClient() {
	if *id == "" {
		*id = randID(7)
	}

	// Create an HTTP client with HTTP/2 support
	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Note: In production, use proper certificate validation
			},
		},
	}

	// Add authorization header to requests
	baseURL := "https://" + *dom + "/announce"

	// Set the URL with query parameter for ID
	url := baseURL + "?id=" + *id

	// Create a request interceptor to add Authorization header
	originalTransport := client.Transport
	client.Transport = &authTransport{
		transport: originalTransport,
		token:     *token,
	}

	// Create the listener with proper URL
	ln, err := h2rev2.NewListener(client, url, *id)
	if err != nil {
		log.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	pubURL := fmt.Sprintf("https://%s.%s", *id, *dom)
	log.Printf("🔗 %s → 127.0.0.1:%d", pubURL, *port)

	upstream, _ := neturl.Parse(fmt.Sprintf("http://127.0.0.1:%d", *port))
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("listener closed: %v", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			http.Serve(&singleConnListener{c: c}, proxy)
		}(conn)
	}
}

/* ---------------- helpers ---------------- */

// one-shot listener so we can feed a single net.Conn into http.Serve
type singleConnListener struct {
	c    net.Conn
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var n net.Conn
	l.once.Do(func() { n, l.c = l.c, nil })
	if n == nil {
		return nil, io.EOF
	}
	return n, nil
}
func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "single" }

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
	switch *mode {
	case "host":
		runHost()
	case "client":
		runClient()
	default:
		log.Fatalf("unknown mode %q", *mode)
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
	return t.transport.RoundTrip(req)
}
