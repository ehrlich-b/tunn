package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
)

func TestGrantCommandCredentialFileAndLifecycle(t *testing.T) {
	dir := t.TempDir()
	ownerPath := filepath.Join(dir, "owner-token")
	owner := "synthetic-owner-token"
	if err := os.WriteFile(ownerPath, []byte(owner), 0600); err != nil {
		t.Fatal(err)
	}
	grant := store.Grant{ID: "synthetic-grant-id", EndpointID: "build", Label: "client B", ExpiresAt: time.Now().Add(time.Hour), RequestLimit: 20}
	token := store.GrantTokenPrefix + strings.Repeat("x", 43)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+owner {
			t.Error("owner authentication missing")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case "POST":
			var input struct {
				Endpoint string `json:"endpoint"`
				Label    string `json:"label"`
				TTL      int64  `json:"ttl_seconds"`
				Requests int64  `json:"request_limit"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.Endpoint != "build" || input.Label != "client B" || input.TTL != 1800 || input.Requests != 20 {
				t.Errorf("input=%+v", input)
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"grant": grant, "token": token})
		case "GET":
			_ = json.NewEncoder(w).Encode(map[string]any{"grants": []store.Grant{grant}})
		case "DELETE":
			if r.URL.Path != "/api/grants/"+grant.ID {
				t.Error(r.URL.Path)
			}
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	common := []string{"--server", server.URL, "--owner-token-file", ownerPath, "--ca-cert", caPath}
	tokenPath := filepath.Join(dir, "client-token")
	args := append([]string{"create"}, common...)
	args = append(args, "--out", tokenPath, "--for", "client B", "--expires", "30m", "--requests", "20", "build")
	var out, diagnostics bytes.Buffer
	if err := executeGrant(context.Background(), args, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String()+diagnostics.String(), token) || strings.Contains(out.String()+diagnostics.String(), owner) {
		t.Fatal("credential printed")
	}
	saved, err := os.ReadFile(tokenPath)
	if err != nil || string(saved) != token+"\n" {
		t.Fatal("credential not saved", err)
	}
	info, err := os.Stat(tokenPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credential file permissions", err)
	}
	before := calls
	if err := executeGrant(context.Background(), args, &out, &diagnostics); err == nil || calls != before {
		t.Fatal("existing token file overwritten or remote grant orphaned")
	}
	for _, action := range []string{"list", "revoke"} {
		args := append([]string{action}, common...)
		if action == "revoke" {
			args = append(args, grant.ID)
		} else {
			args = append(args, "build")
		}
		if err := executeGrant(context.Background(), args, &out, &diagnostics); err != nil {
			t.Fatal(action, err)
		}
	}
	if calls != 3 {
		t.Fatalf("API calls=%d", calls)
	}
}
