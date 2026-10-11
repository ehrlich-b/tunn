package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
	"github.com/ehrlich-b/tunn/internal/sshfront"
)

func runKeys(args []string) {
	if err := executeKeys(args, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func executeKeys(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "--help" {
		_, _ = fmt.Fprintln(out, "tunn keys add <public-key-file> | list | remove <SHA256:fingerprint>")
		return nil
	}
	method := http.MethodGet
	var body []byte
	query := ""
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("keys list takes no arguments")
		}
	case "add":
		if len(args) != 2 {
			return fmt.Errorf("keys add requires a public-key file")
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		key, err := sshfront.ParseKey(string(data))
		if err != nil {
			return err
		}
		body, err = json.Marshal(map[string]string{"public_key": key.PublicKey})
		if err != nil {
			return err
		}
		method = http.MethodPost
	case "remove":
		if len(args) != 2 {
			return fmt.Errorf("keys remove requires a fingerprint")
		}
		method = http.MethodDelete
		query = "?fingerprint=" + url.QueryEscape(args[1])
	default:
		return fmt.Errorf("unknown keys action")
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	token, err := client.LoadToken()
	if err != nil {
		return err
	}
	server := cfg.ServerAddr
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("SSH key owner API requires an HTTPS origin")
	}
	u.Path = "/api/ssh/keys"
	u.RawQuery = strings.TrimPrefix(query, "?")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	r.Header.Set("Content-Type", "application/json")
	transport := relaytransport.Transport(cfg.Insecure || *insecure)
	defer transport.CloseIdleConnections()
	hc := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := hc.Do(r)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode >= 300 {
		return fmt.Errorf("SSH key API: HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	_, err = out.Write(data)
	return err
}
