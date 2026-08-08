package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestGenerateEndpointToken(t *testing.T) {
	first, firstDigest, err := GenerateEndpointToken()
	if err != nil {
		t.Fatal(err)
	}
	second, secondDigest, err := GenerateEndpointToken()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || string(firstDigest) == string(secondDigest) {
		t.Fatal("generated endpoint tokens are not unique")
	}
	if !strings.HasPrefix(first, endpointTokenPrefix) {
		t.Fatalf("token %q has wrong prefix", first)
	}
	want := sha256.Sum256([]byte(first))
	if string(firstDigest) != string(want[:]) {
		t.Fatal("returned digest does not match token")
	}
}

func TestSaveAndLoadEndpointToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	token, _, err := GenerateEndpointToken()
	if err != nil {
		t.Fatal(err)
	}

	path, err := SaveEndpointToken("Work-Tools", token)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(home, ".tunn", "endpoints", "work-tools.token")
	if path != wantPath {
		t.Fatalf("path = %q, want %q", path, wantPath)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0600 {
		t.Fatalf("token permissions = %o, want 600", permissions)
	}

	loaded, err := LoadEndpointToken("work-tools")
	if err != nil {
		t.Fatal(err)
	}
	if loaded != token {
		t.Fatalf("loaded token differs from saved token")
	}
}

func TestSaveEndpointTokenRejectsUnsafeName(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	token, _, err := GenerateEndpointToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../escape", "/absolute", "bad/name", "-leading", "trailing-"} {
		if _, err := SaveEndpointToken(name, token); err == nil {
			t.Fatalf("SaveEndpointToken accepted unsafe name %q", name)
		}
	}
}

func TestRotateEndpointTokenReplacesFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first, _, err := GenerateEndpointToken()
	if err != nil {
		t.Fatal(err)
	}
	path, err := SaveEndpointToken("database", first)
	if err != nil {
		t.Fatal(err)
	}
	second, rotatedPath, err := RotateEndpointToken("database")
	if err != nil {
		t.Fatal(err)
	}
	if second == first || rotatedPath != path {
		t.Fatal("rotation did not replace the endpoint token")
	}
	loaded, err := LoadEndpointToken("database")
	if err != nil || loaded != second {
		t.Fatalf("loaded rotated token = %q, %v", loaded, err)
	}
	if temporary, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".database.*.tmp")); len(temporary) != 0 {
		t.Fatalf("temporary token files remain: %v", temporary)
	}
}

func TestWatchEndpointTokenSendsDigestOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first, firstDigest, err := GenerateEndpointToken()
	if err != nil {
		t.Fatal(err)
	}
	path, err := SaveEndpointToken("tools", first)
	if err != nil {
		t.Fatal(err)
	}
	serveClient := &ServeClient{EndpointTokenPath: path}
	sender := &mockEstablishTunnelClient{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveClient.watchEndpointToken(ctx, sender, firstDigest, time.Millisecond)

	second, secondDigest, err := GenerateEndpointToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveEndpointToken("tools", second); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		sender.mu.Lock()
		messages := append([]*pb.TunnelMessage(nil), sender.sentMsgs...)
		sender.mu.Unlock()
		for _, message := range messages {
			update := message.GetUpdateAccessToken()
			if update == nil {
				continue
			}
			if !bytes.Equal(update.AccessTokenSha256, secondDigest) {
				t.Fatalf("rotated digest does not match token")
			}
			if bytes.Contains(update.AccessTokenSha256, []byte(second)) {
				t.Fatal("plaintext endpoint token was sent")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("token watcher did not send rotation")
}
