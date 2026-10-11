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
	fs.DurationVar(&o.Expires, "expires", 0, "expire the person's access after a duration")
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
		return nil, fmt.Errorf("usage: tunn %s <resource>%s [--server HOST]", command, map[bool]string{true: "", false: " <email>"}[command == "access"])
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

// Enrollment returns to the same publish command after saving device credentials.
func loadOrEnrollWebPublisher(ctx context.Context, server string, insecure bool,
	load func(context.Context, string, bool) (string, *client.CredentialManager, error),
	enroll func(context.Context) error) (string, *client.CredentialManager, error) {
	token, credentials, err := load(ctx, server, insecure)
	if err == nil {
		return token, credentials, nil
	}
	if err = enroll(ctx); err != nil {
		return "", nil, err
	}
	return load(ctx, server, insecure)
}
