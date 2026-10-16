package host

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func accountOperationsAdmin(t *testing.T, id string) store.AdminPrincipal {
	t.Helper()
	token := "operations-fixture-token-0123456789"
	sum := sha256.Sum256([]byte(token))
	p, err := store.AuthenticateAdmin([]store.AdminCredential{{Actor: "fixture-operator", TokenSHA256: hex.EncodeToString(sum[:]), Accounts: []string{id}}}, token)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestAccountOperationsAllIngressAdmissions(t *testing.T) {
	for _, replica := range []bool{false, true} {
		t.Run(fmt.Sprint(replica), func(t *testing.T) {
			p, tunnel, ledger, stream := meteringRelay(t, false, "resumed")
			local := securityDB(t)
			ctx := context.Background()
			acc, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.com"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			p.storage = local
			if replica {
				p.storage = securityReplicaStorage(t, local)
			}
			tunnel.AccountID = acc.ID
			_, grantToken := relayGrant(t, ledger, 10, 10000)
			admin := accountOperationsAdmin(t, acc.ID)
			if _, err = local.OperationsStore().Transition(ctx, admin, acc.ID, "suspended", "fixture hold", 0); err != nil {
				t.Fatal(err)
			}
			for _, route := range []string{"public-http", "cookie-http", "jwt-http", "endpoint-token-http", "grant-http", "mcp", "websocket", "connect", "unix-http"} {
				t.Run(route, func(t *testing.T) {
					r := relayRequest("", "")
					tunnel.EndpointProtocol = "http"
					tunnel.AllowedEmails = nil
					switch route {
					case "cookie-http":
						r.AddCookie(&http.Cookie{Name: "tunn_auth", Value: relayJWT(t, p, acc.PrimaryEmail)})
					case "jwt-http":
						r.Header.Set("Tunn-Authorization", "Bearer "+relayJWT(t, p, acc.PrimaryEmail))
					case "endpoint-token-http":
						token := "tunn_ep_fixture"
						sum := sha256.Sum256([]byte(token))
						tunnel.updateAccessTokenDigest(sum[:])
						r.Header.Set("Tunn-Authorization", "Bearer "+token)
					case "grant-http":
						r.Header.Set("Authorization", "Bearer "+grantToken)
					case "mcp":
						r.URL.Path = "/mcp"
					case "websocket":
						r.Method = "GET"
						r.Header.Set("Connection", "Upgrade")
						r.Header.Set("Upgrade", "websocket")
					case "connect":
						tunnel.EndpointProtocol = "tcp"
						r.Method = "CONNECT"
						r.URL.Path = common.TCPConnectPath
						r.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
					}
					w := httptest.NewRecorder()
					p.proxyToLocal(w, r, tunnel.TunnelID)
					if w.Code != 403 || w.Header().Get("Tunn-Limit-Reason") != "account_suspended" {
						t.Fatalf("%d %s", w.Code, w.Body.String())
					}
				})
			}
			if len(stream.sentMsgs) != 0 {
				t.Fatal("suspended request reached publisher")
			}
			if _, err = local.OperationsStore().Transition(ctx, admin, acc.ID, "active", "review done", 1); err != nil {
				t.Fatal(err)
			}
			tunnel.EndpointProtocol = "http"
			tunnel.updateAccessTokenDigest(nil)
			w := httptest.NewRecorder()
			p.proxyToLocal(w, relayRequest("", ""), tunnel.TunnelID)
			if w.Code != 200 || w.Body.String() != "resumed" {
				t.Fatalf("resume=%d %s", w.Code, w.Body.String())
			}
		})
	}
}
func TestAccountOperationsPublisherAndHostAdmissions(t *testing.T) {
	s := paidHostFixture(t)
	token := createTestJWT("owner@example.com", s.cfg.JWTSecret)
	if w := hostRequest(t, s, "POST", token, fixtureManifest); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	a, err := s.hostAccount(token, false)
	if err != nil {
		t.Fatal(err)
	}
	local := s.storage.(*storage.LocalStorage)
	s.userTokens = map[string]string{a.PrimaryEmail: "tunn_sk_account-fixture-token"}
	ctx := context.Background()
	if _, err = local.OperationsStore().Transition(ctx, accountOperationsAdmin(t, a.ID), a.ID, "suspended", "fixture hold", 0); err != nil {
		t.Fatal(err)
	}
	if w := hostRequest(t, s, "POST", token, fixtureManifest); w.Code != 403 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err = s.hosts.Register(a.ID, common.HostManifest{Machine: "other", Tunnels: []common.HostEndpointSpec{{Name: "other", Kind: "http"}}}); !errors.Is(err, store.ErrSuspended) {
		t.Fatal(err)
	}
	if err = s.accounts.UpdatePlan(a.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if err = s.accounts.ReserveSubdomain(a.ID, "reserved"); !errors.Is(err, store.ErrSuspended) {
		t.Fatal(err)
	}
	if registration, err := local.RegisterTunnel(ctx, "new", a.ID, "fixture"); err != nil || registration.Allowed || registration.Reason != "account_suspended" {
		t.Fatal(registration, err)
	}
	for _, host := range []string{"", "gpu-box"} {
		stream := &mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}
		stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "gpu-http", TunnelKey: s.cfg.WellKnownKey, AuthToken: token, TargetUrl: "http", AllowedEmails: []string{a.PrimaryEmail}}}}
		close(stream.recvQueue)
		hostStream := &hostFixtureStream{mockTunnelStream: stream, ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("tunn-host-id", host))}
		if err = s.EstablishTunnel(hostStream); err == nil {
			t.Fatal("suspended publisher admitted")
		}
		if len(stream.sentMsgs) != 1 || stream.sentMsgs[0].GetRegisterResponse().Success {
			t.Fatal("registration did not explicitly deny")
		}
	}
	userStream := &mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}
	userStream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "configured-user", AuthToken: "tunn_sk_account-fixture-token", CreatorEmail: "other-account@example.invalid", TargetUrl: "http"}}}
	close(userStream.recvQueue)
	if err = s.EstablishTunnel(userStream); err == nil {
		t.Fatal("configured token bypassed its account suspension")
	}
}
func TestAccountOperationsIdleRequestTerminationHooks(t *testing.T) {
	for _, kind := range []string{"buffered-http", "streaming-http", "connect", "websocket-before-upgrade"} {
		t.Run(kind, func(t *testing.T) {
			p, tunnel, _, stream := meteringRelay(t, kind != "buffered-http", "")
			local := securityDB(t)
			acc, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			p.storage = local
			tunnel.AccountID = acc.ID
			tunnel.AllowedEmails = nil
			opened := make(chan struct{}, 1)
			stream.hook = func(msg *pb.TunnelMessage) error {
				if msg.GetHttpRequest() != nil || msg.GetConnectionOpen() != nil {
					select {
					case opened <- struct{}{}:
					default:
					}
				}
				return nil
			}
			r := relayRequest("", "")
			if kind == "connect" {
				tunnel.EndpointProtocol = "tcp"
				r.Method = "CONNECT"
				r.URL.Path = common.TCPConnectPath
				r.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
			}
			if kind == "websocket-before-upgrade" {
				tunnel.Capabilities = map[string]bool{common.CapabilityWebSocketV1: true}
				r.Method = "GET"
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Sec-WebSocket-Version", "13")
				r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			}
			done := make(chan struct{})
			go func() { defer close(done); p.proxyToLocal(httptest.NewRecorder(), r, tunnel.TunnelID) }()
			select {
			case <-opened:
			case <-time.After(2 * time.Second):
				t.Fatal("request did not open")
			}
			if _, err = local.OperationsStore().Transition(context.Background(), accountOperationsAdmin(t, acc.ID), acc.ID, "suspended", "fixture hold", 0); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("idle request survived suspension")
			}
		})
	}
}

type operationsMailSink struct {
	sent int
	fail bool
}

func (s *operationsMailSink) SendMagicLink(to, link string) error {
	if s.fail {
		return errors.New("fixture mail failure")
	}
	s.sent++
	return nil
}

type operationsFailedLimiter struct{ storage.Storage }

func (s operationsFailedLimiter) CheckMagicLinkRateLimit(context.Context, string) (bool, int32, time.Time, error) {
	return false, 0, time.Time{}, errors.New("fixture storage failure")
}
func TestAccountOperationsSignupMailFakeClock(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	now := time.Date(2026, 10, 10, 16, 0, 0, 0, time.UTC)
	local := storage.NewLocalStorageWithClock(db, func() time.Time { return now })
	cfg := webproxyTestConfig()
	cfg.Domain = "tunn.test"
	cfg.PublicAddr = "tunn.test"
	p := &ProxyServer{config: cfg, storage: local, now: func() time.Time { return now }}
	sink := new(operationsMailSink)
	p.emailSender = sink
	request := func(body string) int {
		r := httptest.NewRequest("POST", "https://tunn.test/auth/magic", strings.NewReader(body))
		r.Header.Set("Origin", "https://tunn.test")
		r.RemoteAddr = "192.0.2.4:12000"
		w := httptest.NewRecorder()
		p.handleMagicLinkRequest(w, r)
		return w.Code
	}
	for i := 0; i < 3; i++ {
		if code := request(`{"email":"First@Example.Invalid"}`); code != 200 {
			t.Fatal(code)
		}
	}
	if code := request(`{"email":"first@example.invalid"}`); code != 429 || sink.sent != 3 {
		t.Fatal(code, sink.sent)
	}
	now = now.Add(5 * time.Minute)
	if code := request(`{"email":"first@example.invalid"}`); code != 200 || sink.sent != 4 {
		t.Fatal(code, sink.sent)
	}
	if code := request(`{"email":"bad\r\nBcc: another@example.invalid"}`); code != 400 {
		t.Fatal(code)
	}
	if code := request(`{"email":"first@example.invalid","body":"private request body"}`); code != 400 {
		t.Fatal(code)
	}
	p.storage = operationsFailedLimiter{local}
	if code := request(`{"email":"other@example.invalid"}`); code != 503 || sink.sent != 4 {
		t.Fatal(code, sink.sent)
	}
	p.storage = local
	sink.fail = true
	if code := request(`{"email":"other@example.invalid"}`); code != 500 {
		t.Fatal(code)
	}
	now = now.Add(5 * time.Minute)
	for i := 0; i < 5; i++ {
		if !p.checkDeviceCodeRateLimit("192.0.2.5") {
			t.Fatal("signup blocked too soon")
		}
	}
	if p.checkDeviceCodeRateLimit("192.0.2.5") {
		t.Fatal("signup limiter absent")
	}
	now = now.Add(5 * time.Minute)
	if !p.checkDeviceCodeRateLimit("192.0.2.5") {
		t.Fatal("signup window did not reset")
	}
}
func TestAccountOperationsStripeAdapterAndDurableIntake(t *testing.T) {
	local := securityDB(t)
	p := &ProxyServer{storage: local, config: &config.Config{StripeWebhookSecret: "whsec_local_fixture"}}
	fixtures := []string{
		`{"id":"checkout","type":"checkout.session.completed","created":100,"data":{"object":{"customer":"cus_fixed","subscription":"sub_fixed","mode":"subscription","customer_email":"untrusted@example.invalid","metadata":{"account_id":"untrusted"}}}}`,
		`{"id":"deleted","type":"customer.subscription.deleted","created":1,"data":{"object":{"id":"sub_fixed","customer":"cus_fixed","status":"canceled"}}}`,
		`{"id":"unknown","type":"invoice.future","data":{"object":{}}}`,
	}
	for _, body := range fixtures {
		for repeat := 0; repeat < 2; repeat++ {
			r := httptest.NewRequest("POST", "https://tunn.test/webhooks/stripe", strings.NewReader(body))
			timestamp := fmt.Sprint(time.Now().Unix())
			mac := hmac.New(sha256.New, []byte(p.config.StripeWebhookSecret))
			_, _ = mac.Write([]byte(timestamp + "." + body))
			r.Header.Set("Stripe-Signature", "t="+timestamp+",v1="+hex.EncodeToString(mac.Sum(nil)))
			w := httptest.NewRecorder()
			p.handleStripeWebhook(w, r)
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			var result store.BillingResult
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			want := "reconciliation_required"
			if strings.Contains(body, `"checkout"`) {
				want = "checkout_ownership_review_required"
			}
			if strings.Contains(body, `"unknown"`) {
				want = "ignored"
			}
			if result.State != want || result.Duplicate != (repeat == 1) {
				t.Fatal(result)
			}
		}
	}
	if account, err := local.GetAccountByEmail(context.Background(), "untrusted@example.invalid"); err != nil || account != nil {
		t.Fatal("webhook created account by email", account, err)
	}
}

func TestAccountOperationsReplicaBillingReportsAndAuthentication(t *testing.T) {
	local := securityDB(t)
	ctx := context.Background()
	a, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = local.OperationsStore().BindBilling(ctx, accountOperationsAdmin(t, a.ID), store.BillingMapping{Provider: "fixture", CustomerID: "cus_fixed", SubscriptionID: "sub_fixed", AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	replica := securityReplicaStorage(t, local)
	event := store.BillingEvent{Provider: "fixture", ID: "evt_replica", Type: "subscription.updated", CustomerID: "cus_fixed", SubscriptionID: "sub_fixed", Revision: 1, Plan: "pro", Supported: true}
	for i := 0; i < 2; i++ {
		r, err := replica.ProcessBillingEvent(ctx, event)
		if err != nil || r.State != "applied" || r.Duplicate != (i == 1) {
			t.Fatal(r, err)
		}
	}
	if _, err = local.OperationsStore().Transition(ctx, accountOperationsAdmin(t, a.ID), a.ID, "suspended", "fixture hold", 0); err != nil {
		t.Fatal(err)
	}
	if state, err := replica.LookupAccountStatus(ctx, a.ID); err != nil || state.State != "suspended" || state.Version != 1 {
		t.Fatal(state, err)
	}
	p := &ProxyServer{config: securityConfig(), Domain: "tunn.test", storage: replica}
	for i := 0; i < 6; i++ {
		r := httptest.NewRequest("POST", "https://tunn.test/api/reports", strings.NewReader(`{"category":"billing","endpoint":"api"}`))
		r.Header.Set("Authorization", "Bearer "+relayJWT(t, p, a.PrimaryEmail))
		w := httptest.NewRecorder()
		p.handleReportIntake(w, r)
		want := 202
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("report=%d %s", w.Code, w.Body.String())
		}
		if i == 0 {
			var report store.IncidentReport
			if err = json.Unmarshal(w.Body.Bytes(), &report); err != nil || report.AccountID != a.ID || report.State != "received" {
				t.Fatal(report, err)
			}
		}
	}
	for _, method := range []string{"/internal.LoginNodeDB/ProcessBillingEvent", "/internal.LoginNodeDB/IntakeReport", "/internal.LoginNodeDB/BeginBillingCheckout"} {
		called := false
		handler := func(context.Context, any) (any, error) { called = true; return nil, nil }
		ctx := metadata.NewIncomingContext(ctx, metadata.Pairs("x-node-secret", ""))
		if _, err = nodeSecretInterceptor("")(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, handler); status.Code(err) != codes.FailedPrecondition || called {
			t.Fatal("empty node secret authenticated", err)
		}
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-node-secret", "fixture-node-secret"))
		if _, err = nodeSecretInterceptor("fixture-node-secret")(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, handler); err != nil || !called {
			t.Fatal("authenticated internal RPC failed", err)
		}
	}
}

func (s *operationsMailSink) Send(to, subject, body string) error {
	return fmt.Errorf("unexpected account verification email")
}
