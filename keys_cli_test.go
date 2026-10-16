package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ehrlich-b/tunn/internal/sshfront"
	"github.com/ehrlich-b/tunn/internal/store"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	_ "modernc.org/sqlite"
)

func TestKeysCLIProvesPossession(t *testing.T) {
	for _, source := range []string{"private file", "agent", "public file only"} {
		t.Run(source, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("TUNN_CONFIG_DIR", root)
			t.Setenv("TUNN_ENV", "dev")
			t.Setenv("SSH_AUTH_SOCK", "")
			for _, v := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"} {
				t.Setenv(v, "")
			}
			if err := os.WriteFile(filepath.Join(root, "token"), []byte("owner-fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal(err)
			}
			pub := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
			pubFile := filepath.Join(root, "id_ed25519.pub")
			if err := os.WriteFile(pubFile, []byte(pub), 0600); err != nil {
				t.Fatal(err)
			}
			if source == "private file" {
				block, err := ssh.MarshalPrivateKey(private, "")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(strings.TrimSuffix(pubFile, ".pub"), pem.EncodeToMemory(block), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if source == "agent" {
				// Use a short path for platforms with small Unix socket path limits.
				dir, err := os.MkdirTemp("", "tunn-agent-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(dir)
				socket := filepath.Join(dir, "a")
				listener, err := net.Listen("unix", socket)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				ring := agent.NewKeyring()
				if err := ring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
					t.Fatal(err)
				}
				go func() {
					conn, err := listener.Accept()
					if err == nil {
						defer conn.Close()
						_ = agent.ServeAgent(ring, conn)
					}
				}()
				t.Setenv("SSH_AUTH_SOCK", socket)
			}
			db, err := store.InitForTest()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			account, err := store.NewAccountStore(db).FindOrCreateByEmails([]string{"owner@example.com"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			registry, err := sshfront.NewRegistry(db)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer owner-fixture" {
					t.Error("owner authentication missing")
				}
				var req struct {
					PublicKey string         `json:"public_key"`
					Challenge string         `json:"challenge"`
					Signature *ssh.Signature `json:"signature"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				if req.Signature == nil {
					token, err := registry.BeginProof(r.Context(), req.PublicKey, "owner@example.com", account.ID)
					if err != nil {
						http.Error(w, err.Error(), 500)
						return
					}
					key, _ := sshfront.ParseKey(req.PublicKey)
					w.WriteHeader(202)
					_ = json.NewEncoder(w).Encode(map[string]string{"challenge": token, "email": "owner@example.com", "fingerprint": key.Fingerprint})
					return
				}
				key, err := registry.CompleteProof(r.Context(), account.ID, "owner@example.com", req.PublicKey, req.Challenge, req.Signature)
				if err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				_ = json.NewEncoder(w).Encode(key)
			}))
			defer server.Close()
			t.Setenv("TUNN_SERVER_ADDR", strings.TrimPrefix(server.URL, "https://"))
			var out bytes.Buffer
			err = executeKeys([]string{"add", pubFile}, &out)
			owner, lookupErr := registry.Owner(context.Background(), ssh.FingerprintSHA256(signer.PublicKey()))
			if lookupErr != nil {
				t.Fatal(lookupErr)
			}
			if source == "public file only" {
				if err == nil || owner != "" {
					t.Fatal("public key alone enrolled", owner, err)
				}
				return
			}
			if err != nil || owner != "owner@example.com" || calls.Load() != 2 {
				t.Fatal(owner, calls.Load(), err, out.String())
			}
		})
	}
}
