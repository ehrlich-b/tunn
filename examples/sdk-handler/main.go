// Publish an existing handler. Credentials are passed as values, never flags.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	tunn "github.com/ehrlich-b/tunn/sdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	allowedEmail := os.Getenv("TUNN_ALLOWED_EMAIL")
	if allowedEmail == "" {
		log.Fatal("set TUNN_ALLOWED_EMAIL to the account email allowed to visit this example")
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "Hello from %s\n", r.URL.Path) })
	tunnel, err := tunn.PublishHandler(ctx, handler, tunn.Options{
		Name: os.Getenv("TUNN_NAME"), ServerAddr: os.Getenv("TUNN_SERVER_ADDR"),
		Credentials:   tunn.Credentials{AuthToken: os.Getenv("TUNN_AUTH_TOKEN"), TunnelKey: os.Getenv("TUNN_TUNNEL_KEY")},
		AllowedEmails: []string{allowedEmail},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer tunnel.Close()
	readyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	url, err := tunnel.WaitReady(readyCtx)
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Println(url)
	for event := range tunnel.Events() {
		if event.Err != nil {
			log.Printf("%s: %v", event.State, event.Err)
		}
	}
}
