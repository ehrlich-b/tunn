package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
	"github.com/ehrlich-b/tunn/internal/sshfront"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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
	var key sshfront.Key
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
		key, err = sshfront.ParseKey(string(data))
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
	transport := relaytransport.Transport(cfg.Insecure || *insecure)
	defer transport.CloseIdleConnections()
	hc := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(payload []byte) (int, []byte, error) {
		r, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
		if err != nil {
			return 0, nil, err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
		r.Header.Set("Content-Type", "application/json")
		response, err := hc.Do(r)
		if err != nil {
			return 0, nil, err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		return response.StatusCode, data, err
	}
	status, data, err := request(body)
	if err != nil {
		return err
	}
	if method == http.MethodPost && status == http.StatusAccepted {
		var challenge struct{ Challenge, Email, Fingerprint string }
		if err := json.Unmarshal(data, &challenge); err != nil {
			return err
		}
		if challenge.Challenge == "" || challenge.Email == "" || challenge.Fingerprint != key.Fingerprint {
			return fmt.Errorf("invalid SSH key challenge")
		}
		signer, closeSigner, err := keyEnrollmentSigner(args[1], key.Fingerprint)
		if err != nil {
			return err
		}
		defer closeSigner()
		signature, err := signer.Sign(rand.Reader, sshfront.ProofMessage(challenge.Email, challenge.Challenge))
		if err != nil {
			return err
		}
		body, err = json.Marshal(struct {
			PublicKey string         `json:"public_key"`
			Challenge string         `json:"challenge"`
			Signature *ssh.Signature `json:"signature"`
		}{key.PublicKey, challenge.Challenge, signature})
		if err != nil {
			return err
		}
		status, data, err = request(body)
		if err != nil {
			return err
		}
	}
	if status != http.StatusOK {
		return fmt.Errorf("SSH key API: HTTP %d: %s", status, strings.TrimSpace(string(data)))
	}
	_, err = out.Write(data)
	return err
}

// Public-key files prove nothing on their own. Match a private signer exactly;
// encrypted keys can be unlocked by ssh-add before invoking this command.
func keyEnrollmentSigner(publicFile, fingerprint string) (ssh.Signer, func(), error) {
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		conn, err := net.DialTimeout("unix", socket, 3*time.Second)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			signers, err := agent.NewClient(conn).Signers()
			if err == nil {
				for _, signer := range signers {
					if ssh.FingerprintSHA256(signer.PublicKey()) == fingerprint {
						return signer, func() { conn.Close() }, nil
					}
				}
			}
			conn.Close()
		}
	}
	if strings.HasSuffix(publicFile, ".pub") {
		data, err := os.ReadFile(strings.TrimSuffix(publicFile, ".pub"))
		if err == nil {
			signer, err := ssh.ParsePrivateKey(data)
			if err == nil && ssh.FingerprintSHA256(signer.PublicKey()) == fingerprint {
				return signer, func() {}, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("SSH key enrollment requires its matching private key beside the .pub file or loaded with ssh-add; alternatively use SSH login --email with that key")
}
