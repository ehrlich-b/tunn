package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/webhook"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

func TestWebhookPrivateSecretStorageAndReload(t *testing.T) {
	t.Setenv("TUNN_CONFIG_DIR", t.TempDir())
	path, err := SaveWebhookSecret("hook", []byte("fixture-key"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("key file permissions")
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil || dir.Mode().Perm() != 0700 {
		t.Fatal("key directory permissions")
	}
	c := &ServeClient{TargetURL: "http://localhost:80", WebhookPolicy: &pb.WebhookPolicy{Provider: "stripe", ToleranceSeconds: 300}, WebhookSecretPath: path}
	p, err := c.registrationWebhookPolicy()
	if err != nil || string(p.Secret) != "fixture-key" {
		t.Fatal("registration did not load key")
	}
	path, err = SaveWebhookSecret("hook", []byte("fixture-rotated"))
	if err != nil {
		t.Fatal(err)
	}
	p, err = c.registrationWebhookPolicy()
	if err != nil || string(p.Secret) != "fixture-rotated" {
		t.Fatal("reconnect did not reload key")
	}
	if len(c.WebhookPolicy.Secret) != 0 {
		t.Fatal("source policy mutated")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.registrationWebhookPolicy(); err == nil {
		t.Fatal("permissive file accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWebhookSecret(symlink); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := LoadWebhookSecret(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	for _, value := range []string{"", "\n", strings.Repeat("x", 4097)} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadWebhookSecret(path); err == nil {
			t.Fatal("invalid secret size accepted")
		}
	}
	for _, value := range []string{"key\n", "key\r\n", " key "} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadWebhookSecret(path)
		if err != nil || string(got) != strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r") {
			t.Fatal("key content changed")
		}
	}
	if _, err := SaveWebhookSecret("../escape", []byte("key")); err == nil {
		t.Fatal("unsafe endpoint name accepted")
	}
	for _, key := range []string{"key\n", "key\r", "key\r\n", " key "} {
		stored, err := SaveWebhookSecret("hook", []byte(key))
		if err != nil {
			t.Fatal(err)
		}
		c.WebhookSecretPath = stored
		for i := 0; i < 2; i++ {
			policy, err := c.registrationWebhookPolicy()
			if err != nil || string(policy.Secret) != key {
				t.Fatal("stored key bytes changed on registration/reconnect")
			}
		}
	}
}

type webhookNegotiationFixture struct {
	pb.UnimplementedTunnelServiceServer
	capability bool
	registered chan *pb.RegisterClient
}

func (f *webhookNegotiationFixture) EstablishTunnel(s grpc.BidiStreamingServer[pb.TunnelMessage, pb.TunnelMessage]) error {
	msg, err := s.Recv()
	if err != nil {
		return err
	}
	f.registered <- msg.GetRegisterClient()
	caps := []string{}
	if f.capability {
		caps = append(caps, webhook.Capability)
	}
	if err := s.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://hook.tunn.test", Capabilities: caps}}}); err != nil {
		return err
	}
	// An older relay may queue traffic immediately after registering. The
	// publisher must reject its missing capability before dispatching traffic.
	_ = s.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: "unsupported-relay-origin-attempt", Method: "POST", Path: "/webhook", Body: []byte("fixture")}}})
	<-s.Context().Done()
	return s.Context().Err()
}
func TestWebhookCapabilityNegotiation(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-relay", true: "new-relay"}[supported], func(t *testing.T) {
			var originHits atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originHits.Add(1) }))
			defer origin.Close()
			fixture := &webhookNegotiationFixture{capability: supported, registered: make(chan *pb.RegisterClient, 1)}
			gs := grpc.NewServer()
			pb.RegisterTunnelServiceServer(gs, fixture)
			relay := httptest.NewUnstartedServer(http.HandlerFunc(gs.ServeHTTP))
			relay.EnableHTTP2 = true
			relay.StartTLS()
			defer relay.Close()
			defer gs.Stop()
			pool := x509.NewCertPool()
			pool.AddCert(relay.Certificate())
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var ready atomic.Bool
			c := &ServeClient{TunnelID: "hook", TargetURL: origin.URL, ServerAddr: relay.Listener.Addr().String(), RelayTLSConfig: &tls.Config{RootCAs: pool}, Quiet: true, WebhookPolicy: &pb.WebhookPolicy{Provider: "slack", Secret: []byte("fixture-key"), ToleranceSeconds: 300}, OnRegistered: func(string) { ready.Store(true); cancel() }}
			err := c.Run(ctx)
			reg := <-fixture.registered
			if reg.WebhookPolicy == nil || !bytes.Equal(reg.WebhookPolicy.Secret, []byte("fixture-key")) {
				t.Fatal("policy missing from registration")
			}
			if supported {
				if !ready.Load() || !errors.Is(err, context.Canceled) {
					t.Fatalf("supported relay: %v", err)
				}
			} else {
				if ready.Load() || originHits.Load() != 0 || err == nil || !strings.Contains(err.Error(), "relay lacks webhook") {
					t.Fatalf("old relay: %v", err)
				}
			}
		})
	}
}
func TestWebhookClientValidation(t *testing.T) {
	for _, c := range []*ServeClient{
		{WebhookSecretPath: "fixture"},
		{EndpointProtocol: "tcp", WebhookPolicy: &pb.WebhookPolicy{Provider: "github", Secret: []byte("key"), ToleranceSeconds: 300}},
		{PublicPath: "/mcp", WebhookPolicy: &pb.WebhookPolicy{Provider: "github", Secret: []byte("key"), ToleranceSeconds: 300}},
		{WebhookPolicy: &pb.WebhookPolicy{Provider: "bad", Secret: []byte("key"), ToleranceSeconds: 300}},
	} {
		if _, err := c.registrationWebhookPolicy(); err == nil {
			t.Fatal("invalid client policy accepted")
		}
	}
}
