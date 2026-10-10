// Publish an already running local HTTP origin.
package main

import (
	"context"
	"fmt"
	"log"
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
	origin := os.Getenv("TUNN_ORIGIN")
	if origin == "" {
		origin = "http://127.0.0.1:8080"
	}
	tunnel, err := tunn.Publish(ctx, tunn.Options{
		Origin: origin, Name: os.Getenv("TUNN_NAME"), ServerAddr: os.Getenv("TUNN_SERVER_ADDR"),
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
	if err := tunnel.Wait(); err != nil && ctx.Err() == nil {
		log.Print(err)
	}
}
