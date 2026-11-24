package host

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

// Keep the production client regression in ordinary Go gates too; the browser
// journey separately exercises signed payment as the source of the plan change.
func TestPayJourneyLimitPublisherResumesWithoutRestart(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	local := storage.NewLocalStorage(db)
	p := &ProxyServer{config: securityConfig(), storage: autoStripeStorage{LocalStorage: local}}
	publishers := newPayJourneyPublishers(t, p, db)
	account, err := local.FindOrCreateByEmails(context.Background(), []string{"limit-buyer@example.com"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := publishers.beforePayment(account); err != nil {
		t.Fatal(err)
	}
	activated := time.Now()
	if err := local.UpdatePlan(context.Background(), account.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if err := publishers.afterPayment(activated); err != nil {
		t.Fatal(err)
	}
}

// Every publisher enters ServeClient.Run exactly once before payment. The sixth
// must stay in that call after refusal and recover using the client's backoff.
type payJourneyPublisher struct {
	client *client.ServeClient
	events chan client.LifecycleEvent
	done   chan struct{}
	err    error
	runs   atomic.Int32
}

type payJourneyPublishers struct {
	p                *ProxyServer
	local            *storage.LocalStorage
	ctx              context.Context
	serverAddr       string
	tlsConfig        *tls.Config
	token, accountID string
	target           string
	publishers       []*payJourneyPublisher
	sixth            *payJourneyPublisher
	before           map[string]*TunnelConnection
	facts            map[string]any
	pid              int
}

func newPayJourneyPublishers(t *testing.T, p *ProxyServer, db *sql.DB) *payJourneyPublishers {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "paid limit fixture: "+r.URL.Path)
	}))
	t.Cleanup(origin.Close)
	ledger, err := metering.New(db, metering.WithAccountPlans())
	if err != nil {
		t.Fatal(err)
	}
	relay := NewTunnelServer(p.config, nil, nil, p.storage)
	relay.SetSharingBackend(ledger)
	p.tunnelServer = relay
	p.usageBuffer = NewUsageBuffer()
	server := grpc.NewServer()
	pb.RegisterTunnelServiceServer(server, relay)
	tlsRelay := httptest.NewUnstartedServer(http.HandlerFunc(server.ServeHTTP))
	tlsRelay.EnableHTTP2 = true
	tlsRelay.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(tlsRelay.Certificate())
	f := &payJourneyPublishers{p: p, local: p.storage.(autoStripeStorage).LocalStorage, ctx: ctx,
		serverAddr: tlsRelay.Listener.Addr().String(), tlsConfig: &tls.Config{RootCAs: pool},
		before: map[string]*TunnelConnection{}, facts: map[string]any{}, pid: os.Getpid(), target: origin.URL}
	t.Cleanup(func() {
		cancel()
		for _, publisher := range f.publishers {
			select {
			case <-publisher.done:
			case <-time.After(5 * time.Second):
				t.Error("publisher did not stop on cancellation")
			}
		}
		server.Stop()
		tlsRelay.Close()
	})
	f.facts["publisher_kind"] = "embedded ServeClient.Run over loopback TLS gRPC"
	return f
}

func (f *payJourneyPublishers) start(name string) *payJourneyPublisher {
	publisher := &payJourneyPublisher{events: make(chan client.LifecycleEvent, 128), done: make(chan struct{})}
	publisher.client = &client.ServeClient{
		TunnelID: name, TargetURL: f.target, ServerAddr: f.serverAddr, RelayTLSConfig: f.tlsConfig,
		AuthToken: f.token, TunnelKey: f.p.config.WellKnownKey, Public: true, RequireSharing: true, Quiet: true,
		OnLifecycle: func(event client.LifecycleEvent) {
			select {
			case publisher.events <- event:
			case <-f.ctx.Done():
			}
		},
	}
	f.publishers = append(f.publishers, publisher)
	go func() {
		publisher.runs.Add(1)
		publisher.err = publisher.client.Run(f.ctx)
		close(publisher.done)
	}()
	return publisher
}

func (f *payJourneyPublishers) waitFor(publisher *payJourneyPublisher, state client.LifecycleState) (client.LifecycleEvent, error) {
	timeout := time.NewTimer(40 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case <-publisher.done:
			return client.LifecycleEvent{}, fmt.Errorf("%s Run exited before %s: %v", publisher.client.TunnelID, state, publisher.err)
		case event := <-publisher.events:
			if event.State == state {
				return event, nil
			}
			if state == client.StateReconnecting && event.State == client.StateReady {
				return event, fmt.Errorf("sixth registered before payment")
			}
		case <-timeout.C:
			return client.LifecycleEvent{}, fmt.Errorf("%s did not reach %s", publisher.client.TunnelID, state)
		case <-f.ctx.Done():
			return client.LifecycleEvent{}, f.ctx.Err()
		}
	}
}

func (f *payJourneyPublishers) forward(name string) error {
	tunnel, ok := f.p.tunnelServer.GetTunnel(name)
	if !ok {
		return fmt.Errorf("%s is not registered", name)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	request := httptest.NewRequest("GET", "/usable-limit/"+name, nil).WithContext(ctx)
	response := httptest.NewRecorder()
	if err := f.p.proxyHTTPOverGRPC(response, request, tunnel); err != nil {
		return err
	}
	if response.Code != 200 || response.Body.String() != "paid limit fixture: /usable-limit/"+name {
		return fmt.Errorf("%s forwarding: %d %q", name, response.Code, response.Body.String())
	}
	return nil
}

func (f *payJourneyPublishers) beforePayment(account *storage.Account) error {
	f.accountID = account.ID
	f.token = createTestJWT(account.PrimaryEmail, f.p.config.JWTSecret)
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("pay-limit-%d", i)
		if _, err := f.waitFor(f.start(name), client.StateReady); err != nil {
			return err
		}
		f.before[name], _ = f.p.tunnelServer.GetTunnel(name)
		if err := f.forward(name); err != nil {
			return err
		}
	}
	count, err := f.local.GetTunnelCount(f.ctx, account.ID)
	if err != nil || count != 5 {
		return fmt.Errorf("before count: %d %v", count, err)
	}
	f.sixth = f.start("pay-limit-6")
	event, err := f.waitFor(f.sixth, client.StateReconnecting)
	if err != nil {
		return err
	}
	if client.RegistrationCode(event.Err) != "tunnel_limit" || !strings.Contains(event.Err.Error(), "Free tunnel limit reached: 5/5") || event.RetryDelay <= 0 {
		return fmt.Errorf("sixth before payment: %+v", event)
	}
	if _, ok := f.p.tunnelServer.GetTunnel("pay-limit-6"); ok {
		return fmt.Errorf("refused sixth appeared in relay")
	}
	f.facts["before_count"], f.facts["before_limit"] = count, 5
	f.facts["before_refusal"] = event.Err.Error()
	f.facts["before_error_code"] = client.RegistrationCode(event.Err)
	f.facts["sixth_refused_while_running"] = true
	f.facts["credential_sha256_before"] = fmt.Sprintf("%x", sha256.Sum256([]byte(f.token)))
	f.facts["publisher_pid_before"] = f.pid
	return nil
}

func (f *payJourneyPublishers) afterPayment(start time.Time) error {
	// Observe the already-running client; payment never starts or retries it.
	if _, err := f.waitFor(f.sixth, client.StateReady); err != nil {
		return err
	}
	if err := f.forward("pay-limit-6"); err != nil {
		return err
	}
	usable := time.Now()
	for name, before := range f.before {
		current, ok := f.p.tunnelServer.GetTunnel(name)
		if !ok || current != before || !current.Connected.Equal(before.Connected) {
			return fmt.Errorf("%s publisher restarted", name)
		}
		if err := f.forward(name); err != nil {
			return err
		}
	}
	count, err := f.local.GetTunnelCount(f.ctx, f.accountID)
	if err != nil || count != 6 {
		return fmt.Errorf("after count: %d %v", count, err)
	}
	if os.Getpid() != f.pid {
		return fmt.Errorf("publisher process changed")
	}
	f.facts["after_count"], f.facts["after_limit"] = count, storage.ProTunnelLimit
	f.facts["sixth_registered"], f.facts["sixth_http_status"] = true, 200
	f.facts["persistent_publishers"], f.facts["publisher_restarts"], f.facts["new_logins"] = len(f.before), 0, 0
	for _, publisher := range f.publishers {
		if publisher.runs.Load() != 1 || publisher.client.AuthToken != f.token {
			return fmt.Errorf("%s restarted or changed credential", publisher.client.TunnelID)
		}
		select {
		case <-publisher.done:
			return fmt.Errorf("%s Run exited: %v", publisher.client.TunnelID, publisher.err)
		default:
		}
	}
	f.facts["serve_client_run_calls"] = len(f.publishers)
	f.facts["sixth_run_calls"] = f.sixth.runs.Load()
	f.facts["automatic_registration_retry"] = true
	f.facts["sixth_running_after_activation"] = true
	f.facts["credential_sha256_after"] = fmt.Sprintf("%x", sha256.Sum256([]byte(f.sixth.client.AuthToken)))
	f.facts["publisher_pid_after"] = os.Getpid()
	f.facts["signed_webhook_sent_at"] = start.UTC().Format(time.RFC3339Nano)
	f.facts["sixth_usable_at"] = usable.UTC().Format(time.RFC3339Nano)
	f.facts["seconds_from_signed_webhook_to_usable_limit"] = usable.Sub(start).Seconds()
	return nil
}
