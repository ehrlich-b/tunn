package host

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/store"
)

// Reconstruct the historical first-renewal boundary with explicit HTTP/stream
// synchronization. A current pass does not establish the historical trigger.
func TestPublisherFirstRenewalSettleTrace(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	clock := func() time.Time { return time.Unix(seconds.Load(), 0) }
	gate := make(chan struct{})
	relay := &persistRelay{t: t, db: db, clock: clock, events: make(chan persistRenewalEvent, 32), refreshGate: gate}
	relay.start()
	defer relay.stop()
	login := durableLogin(t, relay.proxy())
	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	data, _ := json.Marshal(map[string]any{"server": "https://tunn.test", "access_token": login.Access, "refresh_token": login.Refresh, "device_id": login.Device, "expires_at": clock().Add(5 * time.Minute)})
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	token, manager, err := client.LoadTunnelToken(context.Background(), "tunn.test", true)
	if err != nil || manager == nil {
		t.Fatal(err)
	}
	manager.Now = clock
	manager.HTTPClient = &http.Client{Transport: &http.Transport{DialContext: relay.dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("settle")) }))
	defer origin.Close()
	publisher := &client.ServeClient{TunnelID: "build-host-ssh", TargetURL: origin.URL, ServerAddr: "tunn.test:443", AuthToken: token, Credentials: manager, TunnelKey: relay.proxy().config.WellKnownKey, AllowedEmails: []string{"owner@example.com"}, Insecure: true, Quiet: true, DialContext: relay.dial, InitialDelay: 5 * time.Millisecond, MaxReconnectDelay: 50 * time.Millisecond, RenewInterval: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- publisher.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("publisher shutdown stalled")
		}
	}()
	start := clock()
	event := func(want string) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case e := <-relay.events:
				t.Logf("clock=%s event=%s", e.Clock.Sub(start), e.Kind)
				if e.Kind == want {
					return
				}
			case err := <-done:
				t.Fatalf("publisher stopped: %v", err)
			case <-deadline:
				t.Fatalf("event %s stalled", want)
			}
		}
	}
	settle := func() {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			saved := readPersistLogin(t, dir)
			applied, _ := relay.applied.Load().(string)
			_, registered := relay.proxy().tunnelServer.GetTunnel("build-host-ssh")
			if registered && saved.Pending == "" && applied == saved.Access && saved.Expires.After(clock().Add(time.Minute)) {
				t.Logf("clock=%s settled registered=true pending=false applied_current=true expires_in=%s", clock().Sub(start), saved.Expires.Sub(clock()))
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("ten-second settle failed registered=%v pending=%v applied_current=%v expires_in=%s", registered, saved.Pending != "", applied == saved.Access, saved.Expires.Sub(clock()))
			}
			time.Sleep(200 * time.Microsecond)
		}
	}
	event("register-applied")
	settle()
	for i := 0; i < 8; i++ {
		seconds.Add(30)
		t.Logf("clock=%s event=synthetic-step", clock().Sub(start))
		if i < 7 {
			settle()
		}
	}
	event("refresh-start")
	saved := readPersistLogin(t, dir)
	if saved.Pending == "" {
		t.Fatal("renewal began without persisted request identity")
	}
	t.Log("clock=4m0s renewal pending persisted; response held; relay still has previous access token")
	close(gate)
	event("refresh-return")
	event("register-applied")
	settle()
	t.Log("current synchronized first renewal passes; historical scheduling/deadline trigger remains unproven")
}
