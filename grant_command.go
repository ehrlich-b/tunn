package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/store"
)

func runGrant(args []string) {
	if err := executeGrant(context.Background(), args, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tunn grant:", err)
		os.Exit(1)
	}
}

func executeGrant(ctx context.Context, args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tunn grant create|list|revoke [options] <endpoint-or-grant-ID>")
	}
	action := args[0]
	if action != "create" && action != "list" && action != "revoke" {
		return fmt.Errorf("unknown grant action %q", action)
	}
	fs := flag.NewFlagSet("grant "+action, flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	server := fs.String("server", "", "HTTPS owner API origin (default configured relay)")
	ownerFile := fs.String("owner-token-file", "", "account access token file (default saved tunn login)")
	caFile := fs.String("ca-cert", "", "additional trusted CA certificate for a self-hosted relay")
	label := fs.String("for", "", "owner-visible client label")
	ttl := fs.Duration("expires", 30*time.Minute, "grant lifetime (1s through 30 days)")
	limit := fs.Int64("requests", 20, "HTTP admissions, including MCP initialization and discovery")
	tokenPath := fs.String("out", "", "new 0600 file for the one-time grant credential (required for create)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if (action == "list" && fs.NArg() > 1) || (action != "list" && fs.NArg() != 1) {
		return fmt.Errorf("provide an endpoint for create, optional endpoint for list, or grant ID for revoke; put options before it")
	}
	if action == "create" && (*tokenPath == "" || *ttl < time.Second || *ttl > store.MaxGrantLifetime || *limit < 1 || *limit > store.MaxGrantRequests) {
		return fmt.Errorf("create requires --out, lifetime 1s through 30 days, and requests 1 through 1000000")
	}
	baseURL := *server
	if baseURL == "" {
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}
		baseURL = "https://" + cfg.ServerAddr
	}
	var ownerToken string
	var err error
	if *ownerFile != "" {
		data, readErr := os.ReadFile(*ownerFile)
		if readErr != nil {
			return fmt.Errorf("read owner token file: %w", readErr)
		}
		ownerToken = strings.TrimSpace(string(data))
	} else {
		ownerToken, err = client.LoadToken()
		if err != nil {
			return fmt.Errorf("owner login required: %w", err)
		}
	}
	api := &client.GrantClient{BaseURL: baseURL, OwnerToken: ownerToken}
	if *caFile != "" {
		data, err := os.ReadFile(*caFile)
		if err != nil {
			return fmt.Errorf("read CA certificate: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(data) {
			return fmt.Errorf("CA file contains no certificates")
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		defer transport.CloseIdleConnections()
		api.HTTPClient = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}
	switch action {
	case "create":
		// Reserve the file before minting, so an existing credential is never
		// overwritten and a bad destination cannot silently create an orphan.
		file, err := os.OpenFile(*tokenPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("reserve grant token file: %w", err)
		}
		saved := false
		defer func() {
			_ = file.Close()
			if !saved {
				_ = os.Remove(*tokenPath)
			}
		}()
		grant, token, err := api.Create(ctx, fs.Arg(0), *label, *ttl, *limit)
		if err != nil {
			return err
		}
		if _, err = io.WriteString(file, token+"\n"); err == nil {
			err = file.Sync()
		}
		if err == nil {
			err = file.Close()
		}
		if err != nil {
			return fmt.Errorf("save failed for grant %s; revoke it with tunn grant revoke: %w", grant.ID, err)
		}
		saved = true
		return json.NewEncoder(out).Encode(struct {
			Grant     *store.Grant `json:"grant"`
			TokenFile string       `json:"token_file"`
			Route     string       `json:"route"`
		}{grant, *tokenPath, "/mcp"})
	case "list":
		grants, err := api.List(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(grants)
	case "revoke":
		if err := api.Revoke(ctx, fs.Arg(0)); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Revoked", fs.Arg(0))
		return err
	}
	return nil
}
