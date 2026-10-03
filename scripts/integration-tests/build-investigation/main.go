// This executable serves the synthetic fixture or investigates it using the
// official Go MCP SDK. It never calls a hosted model API.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/builddemo"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: build-investigation serve|investigate [flags]")
	}
	if os.Args[1] == "serve" {
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		address := flags.String("listen", "127.0.0.1:0", "loopback listener")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		host, _, err := net.SplitHostPort(*address)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return fmt.Errorf("synthetic fixture must listen on a loopback IP")
		}
		listener, err := net.Listen("tcp", *address)
		if err != nil {
			return err
		}
		fmt.Printf("http://%s/mcp\n", listener.Addr())
		mux := http.NewServeMux()
		mux.Handle("/mcp", builddemo.NewHandler())
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		return server.Serve(listener)
	}
	if os.Args[1] != "investigate" {
		return fmt.Errorf("unknown mode %q", os.Args[1])
	}
	flags := flag.NewFlagSet("investigate", flag.ContinueOnError)
	endpoint := flags.String("endpoint", "", "Streamable HTTP MCP endpoint")
	tokenFile := flags.String("token-file", "", "optional bearer token file (never emitted)")
	authHeader := flags.String("auth-header", "Authorization", "Authorization or Tunn-Authorization")
	caFile := flags.String("ca-cert", "", "optional PEM CA certificate for a local relay")
	host := flags.String("host", "", "optional HTTP Host for local tunnel routing")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if *endpoint == "" || (*authHeader != "Authorization" && *authHeader != "Tunn-Authorization") {
		return fmt.Errorf("endpoint and supported auth-header are required")
	}
	var token string
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(data))
		if token == "" || strings.ContainsAny(token, "\r\n") {
			return fmt.Errorf("token file must contain one nonempty line")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("CA certificate has no valid PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport: headerTransport{base: transport, header: *authHeader, token: token, host: *host},
		Timeout:   10 * time.Second,
		// The transport attaches a credential to every request. Never follow a
		// redirect that could move this credential to a different endpoint.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	report, err := builddemo.Investigate(ctx, builddemo.ClientOptions{Endpoint: *endpoint, HTTPClient: httpClient})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

type headerTransport struct {
	base   http.RoundTripper
	header string
	token  string
	host   string
}

func (transport headerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	if transport.token != "" {
		clone.Header.Set(transport.header, "Bearer "+transport.token)
	}
	if transport.host != "" {
		clone.Host = transport.host
	}
	return transport.base.RoundTrip(clone)
}
