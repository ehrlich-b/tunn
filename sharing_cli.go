package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/cliopts"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
	"github.com/mattn/go-isatty"
)

type sharingOptions struct {
	Endpoint, Email, Server string
	Expires                 time.Duration
	Insecure                bool
}

func parseSharing(command string, args []string) (*sharingOptions, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := new(sharingOptions)
	fs.StringVar(&o.Server, "server", "", "relay address")
	fs.DurationVar(&o.Expires, "expires", 0, "expire the person or group's access after a duration")
	fs.BoolVar(&o.Insecure, "insecure", false, "skip relay certificate verification")
	operands, err := cliopts.ParseInterspersed(fs, args)
	if err != nil {
		return nil, err
	}
	want := 2
	if command == "access" {
		want = 1
	}
	if len(operands) != want || o.Expires < 0 || command != "share" && o.Expires != 0 {
		return nil, fmt.Errorf("usage: tunn %s <resource>%s [--server HOST]", command, map[bool]string{true: "", false: " <email|group:ORG:GROUP>"}[command == "access"])
	}
	o.Endpoint = strings.ToLower(operands[0])
	if want == 2 {
		o.Email = operands[1]
	}
	return o, nil
}
func executeSharing(ctx context.Context, command string, o *sharingOptions, token string, h *http.Client, out io.Writer) error {
	method := "GET"
	if command == "share" {
		method = "POST"
	}
	if command == "unshare" {
		method = "DELETE"
	}
	var expires int64
	if o.Expires > 0 {
		expires = time.Now().Add(o.Expires).UnixMilli()
	}
	data, _ := json.Marshal(struct {
		Email     string `json:"email"`
		ExpiresAt int64  `json:"expires_at,omitempty"`
	}{o.Email, expires})
	req, err := http.NewRequestWithContext(ctx, method, "https://"+o.Server+"/api/sharing/"+o.Endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("sharing failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	_, err = io.Copy(out, resp.Body)
	return err
}
func runSharing(command string, args []string) {
	o, err := parseSharing(command, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if o.Server == "" {
		o.Server = cfg.ServerAddr
	}
	o.Insecure = o.Insecure || cfg.Insecure
	ctx := context.Background()
	token, _, err := client.LoadTunnelToken(ctx, o.Server, o.Insecure)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Sign in as the resource owner with tunn login:", err)
		os.Exit(1)
	}
	transport := relaytransport.Transport(o.Insecure)
	defer transport.CloseIdleConnections()
	if err = executeSharing(ctx, command, o, token, &http.Client{Transport: transport, Timeout: 15 * time.Second}, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Enrollment returns to the same publish command after saving device
// credentials. Without a terminal there is nobody to authorize a device code,
// so a service reports the missing login instead of waiting on one.
func loadOrEnrollWebPublisher(ctx context.Context, server string, insecure, interactive bool,
	load func(context.Context, string, bool) (string, *client.CredentialManager, error),
	enroll func(context.Context) error) (string, *client.CredentialManager, error) {
	token, credentials, err := load(ctx, server, insecure)
	if err == nil || !interactive {
		return token, credentials, err
	}
	if err = enroll(ctx); err != nil {
		return "", nil, err
	}
	return load(ctx, server, insecure)
}

// loadPublisherToken waits out an unreachable login server, so a service that
// starts before its network does not exit. It returns only a missing or
// rejected login, which needs a person.
func loadPublisherToken(ctx context.Context, server string, insecure bool) (string, *client.CredentialManager, error) {
	return loadPublisherTokenWithRetry(ctx, server, insecure, func(err error, delay time.Duration) {
		_, _ = fmt.Fprintf(os.Stderr, "tunn: login renewal unavailable (%v); retrying in %s\n", err, delay.Round(time.Second))
	})
}
func loadPublisherTokenWithRetry(ctx context.Context, server string, insecure bool, retry func(error, time.Duration)) (string, *client.CredentialManager, error) {
	for attempt := 0; ; attempt++ {
		token, credentials, err := client.LoadTunnelToken(ctx, server, insecure)
		if err == nil || credentials == nil || client.LoginRequired(err) || ctx.Err() != nil {
			return token, credentials, err
		}
		delay := client.ReconnectDelay(time.Second, 30*time.Second, attempt)
		retry(err, delay)
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-time.After(delay):
		}
	}
}

// exitIfLoginRequired stops a publisher whose login cannot renew with one
// plain line and a status its service unit does not restart.
func exitIfLoginRequired(err error) {
	if client.LoginRequired(err) {
		_, _ = fmt.Fprintln(os.Stderr, client.LoginRequiredMessage())
		os.Exit(client.ExitLoginRequired)
	}
}

// exitIfRuntimeLoginRequired includes bug reporting guidance after a tunnel stops.
func exitIfRuntimeLoginRequired(err error) {
	if client.LoginRequired(err) {
		_, _ = fmt.Fprintln(os.Stderr, client.LoginRequiredMessage()+" Run tunn report to report a bug.")
		os.Exit(client.ExitLoginRequired)
	}
}

// stdinIsTerminal reports a person at a terminal. A service's /dev/null stdin
// is a character device too, so the mode bits alone would start a browser login.
func stdinIsTerminal() bool {
	fd := os.Stdin.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}
