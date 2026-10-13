package host

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/ehrlich-b/tunn/internal/webhook"
	ipb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

const hookFixtureKey = "edge-webhook-key-fixture"

func webhookHeaders(provider string, body []byte, stamp int64) http.Header {
	raw := strconv.FormatInt(stamp, 10)
	prefix := ""
	switch provider {
	case "stripe", "hmac-sha256":
		prefix = raw + "."
	case "slack":
		prefix = "v0:" + raw + ":"
	}
	mac := hmac.New(sha256.New, []byte(hookFixtureKey))
	_, _ = mac.Write([]byte(prefix))
	_, _ = mac.Write(body)
	digest := hex.EncodeToString(mac.Sum(nil))
	h := make(http.Header)
	switch provider {
	case "stripe":
		h.Set("Stripe-Signature", "t="+raw+",v1="+digest)
	case "github":
		h.Set("X-Hub-Signature-256", "sha256="+digest)
	case "slack":
		h.Set("X-Slack-Signature", "v0="+digest)
		h.Set("X-Slack-Request-Timestamp", raw)
	case "shopify":
		h.Set("X-Shopify-Hmac-Sha256", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	case "hmac-sha256":
		h.Set("X-Webhook-Signature", "sha256="+digest)
		h.Set("X-Webhook-Timestamp", raw)
	}
	return h
}

type hookStack struct {
	proxy  *ProxyServer
	relay  *httptest.Server
	tunnel *TunnelConnection
	hits   atomic.Int64
	reads  atomic.Int64
	ledger *metering.Store
}

type hookReadCounter struct {
	io.ReadCloser
	reads *atomic.Int64
}

func (b *hookReadCounter) Read(buf []byte) (int, error) {
	n, err := b.ReadCloser.Read(buf)
	b.reads.Add(int64(n))
	return n, err
}

func startHookStack(t *testing.T, provider string, buffered, private bool, hostedOptions ...bool) *hookStack {
	t.Helper()
	stack := new(hookStack)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stack.hits.Add(1)
		if r.URL.RequestURI() != "/webhook?raw=1" {
			t.Error("URI changed")
		}
		if r.Header.Get("Tunn-Authorization") != "" || r.Header.Get("Cookie") != "app=keep" || r.Header.Get("Authorization") != "Bearer application-fixture" {
			t.Error("credential sanitation changed")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		w.WriteHeader(202)
		_, _ = w.Write(body)
	}))
	t.Cleanup(origin.Close)
	cfg := &config.Config{Domain: "tunn.test", ClientSecret: "publisher-webhook-fixture", NodeSecret: "cluster-webhook-fixture", JWTSecret: "jwt-webhook-fixture"}
	server := NewTunnelServer(cfg, nil, nil, nil)
	proxy := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: server, storage: storage.NewProxyStorage(), quotaCache: NewQuotaCache(time.Minute)}
	hosted := len(hostedOptions) > 0 && hostedOptions[0]
	if hosted {
		db, err := store.InitForTest()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		local := storage.NewLocalStorage(db)
		if _, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "fixture"); err != nil {
			t.Fatal(err)
		}
		stack.ledger, err = metering.New(db, metering.WithAccountPlans())
		if err != nil {
			t.Fatal(err)
		}
		proxy = securityProxy(local)
		cfg, server = proxy.config, proxy.tunnelServer
		cfg.NodeSecret = "cluster-webhook-fixture" // Required authenticated cross-relay provenance.
		proxy.meter, proxy.planMeter = stack.ledger, true
		server.sharing = stack.ledger
	}
	gs := grpc.NewServer()
	var implementation pb.TunnelServiceServer = server
	if buffered {
		implementation = &sdkBufferedRelay{TunnelServer: server}
	}
	pb.RegisterTunnelServiceServer(gs, implementation)
	proxy.grpcServer = gs
	relay := httptest.NewUnstartedServer(proxy.createHTTP2Router(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = &hookReadCounter{ReadCloser: r.Body, reads: &stack.reads}
		proxy.handleWebProxy(w, r)
	})))
	relay.EnableHTTP2 = true
	relay.StartTLS()
	t.Cleanup(func() { gs.Stop(); relay.Close() })
	pool := x509.NewCertPool()
	pool.AddCert(relay.Certificate())
	ctx, cancel := context.WithCancel(context.Background())
	publisher := &client.ServeClient{TunnelID: "hook", TargetURL: origin.URL, ServerAddr: relay.Listener.Addr().String(), AuthToken: cfg.ClientSecret, RelayTLSConfig: &tls.Config{RootCAs: pool}, Quiet: true, Public: true, RequireSharing: true, WebhookPolicy: &pb.WebhookPolicy{Provider: provider, Secret: []byte(hookFixtureKey), ToleranceSeconds: 300}}
	if hosted {
		publisher.AuthToken = relayJWT(t, proxy, "owner@example.com")
		publisher.TunnelKey = cfg.WellKnownKey
		publisher.RequireUpstreamAuth = true
	}
	if private {
		publisher.RequireSharing = hosted
		publisher.Public = false
		if !hosted {
			publisher.AllowedEmails = []string{"owner@example.com"}
		}
		digest := sha256.Sum256([]byte("tunn_ep_hook-fixture"))
		publisher.AccessTokenSHA256 = digest[:]
	}
	ready := make(chan string, 1)
	publisher.OnRegistered = func(u string) { ready <- u }
	done := make(chan error, 1)
	go func() { done <- publisher.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("publisher did not stop")
		}
	})
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("publisher registration: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not become ready")
	}
	tunnel, ok := server.GetTunnel("hook")
	if !ok || tunnel.WebhookPolicy == nil {
		t.Fatal("policy missing from active endpoint")
	}
	if tunnel.Supports(common.CapabilityHTTPStreamV1) == buffered {
		t.Fatal("wrong forwarding path")
	}
	if hosted && (tunnel.accountQuotaExempt || tunnel.AccountID == "" || tunnel.ResourceID == "" || tunnel.CreatorEmail != "owner@example.com") {
		t.Fatal("hosted publisher lost authenticated account/resource authority")
	}
	stack.proxy = proxy
	stack.relay = relay
	stack.tunnel = tunnel
	return stack
}
func TestWebhookEndToEnd(t *testing.T) {
	body := []byte(" {\n\"unicode\":\"café\",\"padding\":true}\r\n\x00\xff")
	for _, provider := range []string{"stripe", "github", "slack", "shopify", "hmac-sha256"} {
		for _, buffered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/buffered=%t", provider, buffered), func(t *testing.T) {
				s := startHookStack(t, provider, buffered, false)
				ingress := &ProxyServer{Domain: s.proxy.Domain, config: &config.Config{Insecure: true, NodeSecret: s.proxy.config.NodeSecret}, tunnelServer: NewTunnelServer(s.proxy.config, nil, nil, nil), tunnelCache: map[string]string{"hook": s.relay.Listener.Addr().String()}}
				authority := NewInternalServer(s.proxy.tunnelServer, s.relay.Listener.Addr().String(), false)
				authority.proxy = s.proxy
				ingress.nodeClients = map[string]ipb.InternalServiceClient{"publisher": forwardPermissionPeer{server: authority}}
				for _, remote := range []bool{false, true} {
					for _, kind := range []string{"valid", "tampered", "missing", "duplicate", "upgrade"} {
						t.Run(fmt.Sprintf("remote=%t/%s", remote, kind), func(t *testing.T) {
							r := httptest.NewRequest("POST", "https://hook.tunn.test/webhook?raw=1", bytes.NewReader(body))
							r.Header = webhookHeaders(provider, body, time.Now().Unix())
							switch kind {
							case "tampered":
								r.Body = io.NopCloser(strings.NewReader("tampered"))
								r.ContentLength = -1
							case "missing":
								r.Header = make(http.Header)
							case "duplicate":
								for k, v := range r.Header {
									r.Header.Add(k, v[0])
								}
							case "upgrade":
								r.Header.Set("Upgrade", "websocket")
								r.Header.Set("Connection", "Upgrade")
							}
							r.Header.Set("Cookie", "tunn_auth=fixture-secret; app=keep")
							r.Header.Set("Authorization", "Bearer application-fixture")
							r.Header.Set("Tunn-Authorization", "Bearer platform-fixture")
							before := s.hits.Load()
							rec := httptest.NewRecorder()
							if remote {
								ingress.handleWebProxy(rec, r)
							} else {
								s.proxy.handleWebProxy(rec, r)
							}
							if kind == "valid" {
								if rec.Code != 202 || !bytes.Equal(rec.Body.Bytes(), body) || s.hits.Load() != before+1 {
									t.Fatalf("valid: status=%d body=%q hits=%d", rec.Code, rec.Body, s.hits.Load())
								}
							} else {
								if rec.Code != 401 || s.hits.Load() != before || !strings.Contains(rec.Body.String(), "Webhook verification failed:") {
									t.Fatalf("denial: status=%d hits=%d body=%s", rec.Code, s.hits.Load(), rec.Body)
								}
							}
						})
					}
				}
			})
		}
	}
}
func TestWebhookRetainsPrivateAccess(t *testing.T) {
	s := startHookStack(t, "github", false, true)
	body := []byte("signed")
	for _, credential := range []bool{false, true} {
		r := httptest.NewRequest("POST", "https://hook.tunn.test/webhook?raw=1", bytes.NewReader(body))
		r.Header = webhookHeaders("github", body, time.Now().Unix())
		r.Header.Set("Cookie", "app=keep")
		r.Header.Set("Authorization", "Bearer application-fixture")
		if credential {
			r.Header.Set("Tunn-Authorization", "Bearer tunn_ep_hook-fixture")
		}
		rec := httptest.NewRecorder()
		s.proxy.handleWebProxy(rec, r)
		if credential {
			if rec.Code != 202 || s.hits.Load() != 1 {
				t.Fatal("private signed authenticated delivery denied", rec.Code)
			}
		} else {
			if rec.Code == 202 || s.hits.Load() != 0 {
				t.Fatal("signature bypassed private access")
			}
		}
	}
}
func TestWebhookRegistration(t *testing.T) {
	for _, kind := range []string{"valid", "unauthenticated", "invalid-policy", "tcp", "mcp"} {
		t.Run(kind, func(t *testing.T) {
			cfg := testConfig()
			cfg.ClientSecret = "publisher-fixture"
			server := NewTunnelServer(cfg, nil, nil, nil)
			policy := &pb.WebhookPolicy{Provider: "stripe", Secret: []byte(hookFixtureKey), ToleranceSeconds: 300}
			reg := &pb.RegisterClient{TunnelId: "hook", TargetUrl: "http", AuthToken: cfg.ClientSecret, WebhookPolicy: policy, Capabilities: []string{common.CapabilityConnectionStreamV1}, ExposureVersion: 1, ExposureMode: "public"}
			switch kind {
			case "unauthenticated":
				reg.AuthToken = "wrong"
			case "invalid-policy":
				policy.Provider = "unknown"
			case "tcp":
				reg.EndpointProtocol = "tcp"
			case "mcp":
				reg.TargetUrl = "mcp"
			}
			stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
			stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: reg}}
			close(stream.recvQueue)
			stream.onSend = func(m *pb.TunnelMessage) error {
				if res := m.GetRegisterResponse(); res != nil && res.Success {
					tunnel, ok := server.GetTunnel("hook")
					if !ok || tunnel.WebhookPolicy == nil {
						t.Error("registered policy missing")
					}
					if !stringSliceContains(res.Capabilities, webhook.Capability) {
						t.Error("capability missing")
					}
					policy.Secret[0] = 'x' // Config is not aliased into the policy key.
					r := httptest.NewRequest("POST", "/", nil)
					r.Header = webhookHeaders("stripe", nil, time.Now().Unix())
					if err := tunnel.WebhookPolicy.Verify(r, time.Now); err != nil {
						t.Error("policy key aliased", err)
					}
				}
				return stream.mockTunnelStream.Send(m)
			}
			err := server.EstablishTunnel(stream)
			if len(stream.sentMsgs) == 0 {
				t.Fatal("no registration response")
			}
			success := stream.sentMsgs[0].GetRegisterResponse().Success
			if success != (kind == "valid") || kind != "valid" && err == nil {
				t.Fatal("registration validation failed")
			}
			if _, ok := server.GetTunnel("hook"); ok {
				t.Fatal("policy endpoint survived publisher disconnect")
			}
		})
	}
}

func TestWebhookDocsRoute(t *testing.T) {
	p := &ProxyServer{}
	for _, method := range []string{"GET", "HEAD", "POST"} {
		r := httptest.NewRequest(method, "https://tunn.test/docs/webhook-verification", nil)
		rec := httptest.NewRecorder()
		p.handleDocs(rec, r)
		if method == "POST" {
			if rec.Code != 405 {
				t.Fatal("docs accepted POST")
			}
			continue
		}
		if rec.Code != 200 {
			t.Fatal("webhook docs route missing")
		}
		for _, term := range []string{"--verify-webhook=stripe", "--verify-webhook=github", "--verify-webhook=slack", "--verify-webhook=shopify", "--verify-webhook=hmac-sha256", "X-Webhook-Timestamp", "401", "1 MiB", "Deduplicate", "mode 0600"} {
			if !strings.Contains(rec.Body.String(), term) {
				t.Errorf("docs missing %s", term)
			}
		}
	}
	if !strings.Contains(docsHTML, "/docs/webhook-verification") {
		t.Fatal("guide not linked from docs index")
	}
}

// The real account-plan ledger backs this fixture; only its explicit failure
// modes are substituted to exercise unavailable authority before/after reads.
type hookLedgerFailure struct {
	*metering.Store
	charge bool
}

func (b hookLedgerFailure) Admit(ctx context.Context, event *meterpb.Event) (*meterpb.Decision, error) {
	if !b.charge {
		return nil, fmt.Errorf("fixture admission unavailable")
	}
	return b.Store.Admit(ctx, event)
}
func (b hookLedgerFailure) Charge(context.Context, *meterpb.ChargeRequest) (*meterpb.Decision, error) {
	return nil, fmt.Errorf("fixture charge unavailable")
}

func TestWebhookHostedAdmissionAndMetering(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		for _, remote := range []bool{false, true} {
			for _, kind := range []string{"valid", "invalid-signature", "unauthenticated", "wrong-person", "owner-quota", "grant-quota", "grant-byte-budget", "ledger-admit-failure", "ledger-charge-failure", "upstream-auth", "owner-conflict", "suspended"} {
				t.Run(fmt.Sprintf("buffered=%t/remote=%t/%s", buffered, remote, kind), func(t *testing.T) {
					s := startHookStack(t, "github", buffered, true, true)
					body := []byte("raw-body")
					credential := "tunn_ep_hook-fixture"
					wantStatus, wantReads, wantHits := 202, int64(len(body)), int64(1)
					request := func() *http.Request {
						r := httptest.NewRequest("POST", "https://hook.tunn.test/webhook?raw=1", bytes.NewReader(body))
						r.Header = webhookHeaders("github", body, time.Now().Unix())
						r.Header.Set("Cookie", "app=keep")
						r.Header.Set("Authorization", "Bearer application-fixture")
						if credential != "" {
							r.Header.Set("Tunn-Authorization", "Bearer "+credential)
						}
						if !remote {
							r.Body = &hookReadCounter{ReadCloser: r.Body, reads: &s.reads}
						}
						return r
					}
					ingress := &ProxyServer{Domain: s.proxy.Domain, config: &config.Config{Insecure: true, NodeSecret: s.proxy.config.NodeSecret}, tunnelServer: NewTunnelServer(s.proxy.config, nil, nil, nil), tunnelCache: map[string]string{"hook": s.relay.Listener.Addr().String()}}
					authority := NewInternalServer(s.proxy.tunnelServer, s.relay.Listener.Addr().String(), false)
					authority.proxy = s.proxy
					ingress.nodeClients = map[string]ipb.InternalServiceClient{"publisher": forwardPermissionPeer{server: authority}}
					serve := func(r *http.Request) *httptest.ResponseRecorder {
						w := httptest.NewRecorder()
						if remote {
							ingress.handleWebProxy(w, r)
						} else {
							s.proxy.handleWebProxy(w, r)
						}
						return w
					}
					if strings.HasPrefix(kind, "grant-") {
						credential = "tunn_gr_hook-fixture"
						digest := sha256.Sum256([]byte(credential))
						grant := &meterpb.Grant{Owner: s.tunnel.AccountID, Endpoint: "hook", TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), MonthlyRequests: 1, MonthlyBytes: 1000}
						if kind == "grant-byte-budget" {
							grant.MonthlyBytes = 3
						}
						if _, err := s.ledger.CreateGrant(context.Background(), grant); err != nil {
							t.Fatal(err)
						}
					}
					if kind == "owner-quota" {
						metering.WithOwnerBudgets(1, 0)(s.ledger)
					}
					if kind == "owner-quota" || kind == "grant-quota" {
						if w := serve(request()); w.Code != 202 {
							t.Fatalf("initial admission: %d %s", w.Code, w.Body)
						}
						s.reads.Store(0)
						s.hits.Store(0)
					}
					switch kind {
					case "unauthenticated":
						credential = ""
						wantStatus, wantReads, wantHits = 401, 0, 0
					case "wrong-person":
						credential = relayJWT(t, s.proxy, "stranger@example.com")
						wantStatus, wantReads, wantHits = 403, 0, 0
					case "owner-quota", "grant-quota":
						wantStatus, wantReads, wantHits = 429, 0, 0
					case "grant-byte-budget":
						wantStatus, wantReads, wantHits = 429, int64(len(body)), 0
					case "ledger-admit-failure":
						s.proxy.meter = hookLedgerFailure{Store: s.ledger}
						wantStatus, wantReads, wantHits = 503, 0, 0
					case "ledger-charge-failure":
						s.proxy.meter = hookLedgerFailure{Store: s.ledger, charge: true}
						wantStatus, wantReads, wantHits = 503, int64(len(body)), 0
					case "invalid-signature", "upstream-auth":
						wantStatus, wantHits = 401, 0
					case "owner-conflict":
						if _, err := s.ledger.Sharing(context.Background(), &meterpb.SharingRequest{Operation: "register", Owner: "another-owner", Endpoint: "hook", Mode: "private"}); err != nil {
							t.Fatal(err)
						}
						wantStatus, wantReads, wantHits = 503, 0, 0
					case "suspended":
						local := s.proxy.storage.(*storage.LocalStorage)
						if _, err := local.OperationsStore().Transition(context.Background(), accountOperationsAdmin(t, s.tunnel.AccountID), s.tunnel.AccountID, "suspended", "fixture hold", 0); err != nil {
							t.Fatal(err)
						}
						wantStatus, wantReads, wantHits = 403, 0, 0
					}
					r := request()
					if kind == "invalid-signature" {
						r.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
					}
					if kind == "upstream-auth" {
						r.Header.Del("Authorization")
					}
					if kind == "grant-byte-budget" {
						r.ContentLength = -1
					}
					w := serve(r)
					if w.Code != wantStatus || s.reads.Load() != wantReads || s.hits.Load() != wantHits {
						t.Fatalf("status=%d reads=%d origin=%d; want %d/%d/%d: %s", w.Code, s.reads.Load(), s.hits.Load(), wantStatus, wantReads, wantHits, w.Body)
					}
					if kind == "valid" || kind == "invalid-signature" || kind == "grant-byte-budget" {
						out, err := s.ledger.Export(context.Background(), &meterpb.ExportRequest{Owner: s.tunnel.AccountID, Endpoint: "hook", Month: time.Now().UTC().Format("2006-01")})
						if err != nil || len(out.Usage) != 1 {
							t.Fatal("missing request accounting", err)
						}
						wantBytes := int64(len(body))
						if kind == "grant-byte-budget" {
							wantBytes = 3
						}
						if out.Usage[0].RequestBytes != wantBytes {
							t.Fatalf("request charged %d times/bytes; want %d", out.Usage[0].RequestBytes, wantBytes)
						}
						if kind == "invalid-signature" && (len(out.Events) != 1 || out.Events[0].Forwarded || out.Events[0].Reason != "webhook_verification_failed") {
							t.Fatal("invalid delivery missing denial audit")
						}
					}
				})
			}
		}
	}
}

func TestWebhookHostedPublisherCannotReplaceOwnerPolicy(t *testing.T) {
	s := startHookStack(t, "github", false, true, true)
	stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
	stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "hook", TargetUrl: "http", AuthToken: relayJWT(t, s.proxy, "stranger@example.com"), TunnelKey: s.proxy.config.WellKnownKey, CreatorEmail: "owner@example.com", ExposureVersion: 1, ExposureMode: "public", WebhookPolicy: &pb.WebhookPolicy{Provider: "github", Secret: []byte("other-key"), ToleranceSeconds: 300}}}}
	close(stream.recvQueue)
	if err := s.proxy.tunnelServer.EstablishTunnel(stream); err == nil {
		t.Fatal("another publisher replaced the owner policy")
	}
	current, ok := s.proxy.tunnelServer.GetTunnel("hook")
	if !ok || current != s.tunnel {
		t.Fatal("original endpoint lost on conflicting registration")
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header = webhookHeaders("github", nil, time.Now().Unix())
	if err := current.WebhookPolicy.Verify(r, time.Now); err != nil {
		t.Fatal("conflicting publisher changed the key", err)
	}
}

type hookCancellingBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *hookCancellingBody) Read(buf []byte) (int, error) {
	n, err := b.ReadCloser.Read(buf)
	b.cancel()
	return n, err
}
func TestWebhookCancelledBodyCannotOpenOriginRequest(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			p, tunnel, ledger, stream := meteringRelay(t, streaming, "unused")
			var err error
			tunnel.WebhookPolicy, err = webhook.Compile(&pb.WebhookPolicy{Provider: "github", Secret: []byte(hookFixtureKey), ToleranceSeconds: 300})
			if err != nil {
				t.Fatal(err)
			}
			body := []byte("signed-body")
			r := relayRequest(relayJWT(t, p, "owner@example.com"), string(body))
			for key, values := range webhookHeaders("github", body, time.Now().Unix()) {
				r.Header[key] = values
			}
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			r.Body = &hookCancellingBody{ReadCloser: r.Body, cancel: cancel}
			w := httptest.NewRecorder()
			p.handleWebProxy(w, r)
			stream.mu.Lock()
			messages := len(stream.sentMsgs)
			stream.mu.Unlock()
			if w.Code != 502 || messages != 0 {
				t.Fatalf("cancelled upload opened origin: status=%d messages=%d", w.Code, messages)
			}
			out := relayExport(t, ledger)
			if len(out.Usage) != 1 || out.Usage[0].RequestBytes != int64(len(body)) || out.Events[0].Forwarded {
				t.Fatal("cancelled consumed bytes/forwarding not recorded")
			}
		})
	}
}
