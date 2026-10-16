// response-consumer is a standalone importer of the exported Go SDK. Run its
// live gate only against the operator's disposable local relay.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sync"
	"time"

	tunn "github.com/ehrlich-b/tunn/sdk"
)

const prefix = "prefix\n"
const suffix = "suffix\n"

func responseHandler(finish <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "first", Value: "one,fragment=two", Path: "/", Expires: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)})
		http.SetCookie(w, &http.Cookie{Name: "second", Value: "three", Path: "/"})
		w.Header().Add("Trailer", "X-End")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, prefix)
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		select {
		case <-finish:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, suffix)
		w.Header().Add("X-End", "one,two")
		w.Header().Add("X-End", "three")
	})
}

func consumeResponse(response *http.Response, finish func()) error {
	defer response.Body.Close()
	cookies := response.Cookies()
	if response.StatusCode != 202 || len(response.Header.Values("Set-Cookie")) != 2 || len(cookies) != 2 || cookies[0].Name != "first" || cookies[0].Value != "one,fragment=two" || cookies[1].Name != "second" || cookies[1].Value != "three" {
		return fmt.Errorf("response status or repeated cookies changed: status=%d cookies=%v", response.StatusCode, cookies)
	}
	buffer := make([]byte, len(prefix))
	if _, err := io.ReadFull(response.Body, buffer); err != nil {
		return fmt.Errorf("streamed prefix: %w", err)
	}
	if string(buffer) != prefix || len(response.Trailer.Values("X-End")) != 0 {
		return errors.New("prefix or pre-terminal trailer changed")
	}
	finish()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("terminal body read: %w", err)
	}
	if string(body) != suffix || !reflect.DeepEqual(response.Trailer.Values("X-End"), []string{"one,two", "three"}) {
		return fmt.Errorf("suffix or terminal trailers changed: %q %v", body, response.Trailer)
	}
	return nil
}

func run(ctx context.Context, options tunn.Options, consumerOrigin string, client *http.Client) error {
	finishChannel := make(chan struct{})
	finish := sync.OnceFunc(func() { close(finishChannel) })
	defer finish()
	publisher, err := tunn.PublishHandler(ctx, responseHandler(finishChannel), options)
	if err != nil {
		return err
	}
	defer publisher.Close()
	publicURL, err := publisher.WaitReady(ctx)
	if err != nil {
		return err
	}
	public, err := url.Parse(publicURL)
	if err != nil {
		return err
	}
	if consumerOrigin == "" {
		consumerOrigin = publicURL
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, consumerOrigin+"/", nil)
	if err != nil {
		return err
	}
	request.Host = public.Host
	if options.Credentials.EndpointToken != "" {
		request.Header.Set("Tunn-Authorization", "Bearer "+options.Credentials.EndpointToken)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	if err = consumeResponse(response, finish); err != nil {
		return err
	}
	if err = publisher.Close(); err != nil {
		return err
	}
	closed := 0
	for event := range publisher.Events() {
		if event.State == tunn.Closed {
			closed++
		}
	}
	if closed != 1 {
		return fmt.Errorf("SDK finalization count=%d", closed)
	}
	return nil
}

func main() {
	caFile := flag.String("ca", "", "PEM CA for the disposable relay")
	consumerOrigin := flag.String("consumer-origin", "", "local relay HTTP origin; keeps the registered public Host")
	name := flag.String("name", "response-consumer", "disposable tunnel name")
	flag.Parse()
	rootCAs := (*x509.CertPool)(nil)
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(pem) {
			fmt.Fprintln(os.Stderr, "CA file contains no certificates")
			os.Exit(1)
		}
	}
	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}
	options := tunn.Options{Name: *name, ServerAddr: os.Getenv("TUNN_SERVER_ADDR"), Credentials: tunn.Credentials{AuthToken: os.Getenv("TUNN_AUTH_TOKEN"), TunnelKey: os.Getenv("TUNN_TUNNEL_KEY"), EndpointToken: os.Getenv("TUNN_ENDPOINT_TOKEN")}, TLSConfig: tlsConfig, Reconnect: &tunn.ReconnectPolicy{MaxAttempts: 0}, ConnectTimeout: 3 * time.Second}
	if options.ServerAddr == "" {
		fmt.Fprintln(os.Stderr, "TUNN_SERVER_ADDR must identify the disposable relay")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	if err := run(ctx, options, *consumerOrigin, &http.Client{Transport: transport}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("PASS: 2 cookies; streamed prefix and suffix; 2 terminal trailers; 1 SDK Closed event")
}
