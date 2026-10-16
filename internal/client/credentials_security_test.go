package client

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestDurablePublisherRefreshFailureActionable(t *testing.T) {
	manager, state := credentialFixture(t)
	state.Expires = time.Now().Add(-time.Minute)
	if err := saveCredentialState(manager.path, state); err != nil {
		t.Fatal(err)
	}
	manager.HTTPClient = &http.Client{Transport: meteringTransportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("private response"))}, nil
	})}
	publisher := &ServeClient{Credentials: manager}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sender := durableLeaseSender{sent: func(*pb.TunnelMessage) error { t.Error("rejected refresh sent a token"); return nil }}
	err := publisher.maintainDeviceLease(ctx, sender, state.Access, time.Millisecond)
	if err == nil || !terminalCredentialError(err) || !strings.Contains(err.Error(), "tunn login") || strings.Contains(err.Error(), "private response") {
		t.Fatal("publisher hid actionable renewal failure", err)
	}
}
func TestDurableCredentialsRejectSymlinkedLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix no-follow lock guarantee")
	}
	manager, _ := credentialFixture(t)
	dir := filepath.Dir(manager.path)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "credentials.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Token(context.Background(), false); err == nil {
		t.Fatal("symlinked lock accepted")
	}
	info, err := os.Stat(victim)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("lock followed victim symlink", err)
	}
	data, _ := os.ReadFile(victim)
	if string(data) != "untouched" {
		t.Fatal("victim modified")
	}
}
