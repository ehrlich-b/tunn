package host

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestAccountMergePreservesUsageAndGrants(t *testing.T) {
	ctx := context.Background()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	local := storage.NewLocalStorage(db)
	old, err := local.FindOrCreateByEmails(ctx, []string{"old@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	survivor, err := local.FindOrCreateByEmails(ctx, []string{"survivor@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := local.UpdatePlan(ctx, survivor.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	ledger, err := metering.New(db, metering.WithOwnerBudgets(2, 20))
	if err != nil {
		t.Fatal(err)
	}
	token := sha256.Sum256([]byte("tunn_gr_merge-fixture"))
	grant, err := ledger.CreateGrant(ctx, &meterpb.Grant{Owner: old.ID, Endpoint: "merged-api", TokenSha256: token[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), MonthlyRequests: 1, MonthlyBytes: 10, RequestsPerMinute: 1})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("1", 32)
	if d, err := ledger.Admit(ctx, &meterpb.Event{RequestId: id, Owner: old.ID, Endpoint: "merged-api", Caller: "grant:" + grant.Id, AuthMethod: "grant", GrantId: grant.Id, Allowed: true}); err != nil || !d.Allowed {
		t.Fatalf("admit: %v %v", d, err)
	}
	if _, err := ledger.Charge(ctx, &meterpb.ChargeRequest{RequestId: id, RequestBytes: 10}); err != nil {
		t.Fatal(err)
	}
	if err := local.RecordUsage(ctx, old.ID, 10); err != nil {
		t.Fatal(err)
	}
	// Overlapping rows on the survivor must be added, rather than overwritten.
	activeID := strings.Repeat("3", 32)
	if d, err := ledger.Admit(ctx, &meterpb.Event{RequestId: activeID, Owner: survivor.ID, Endpoint: "merged-api", Caller: "grant:" + grant.Id, AuthMethod: "none", Allowed: true}); err != nil || !d.Allowed {
		t.Fatalf("survivor admit: %v %v", d, err)
	}
	if _, err := ledger.Charge(ctx, &meterpb.ChargeRequest{RequestId: activeID, ResponseBytes: 10}); err != nil {
		t.Fatal(err)
	}
	if err := local.RecordUsage(ctx, survivor.ID, 10); err != nil {
		t.Fatal(err)
	}
	merged, err := local.FindOrCreateByEmails(ctx, []string{"old@example.com", "survivor@example.com"}, "github")
	if err != nil || merged.ID != survivor.ID {
		t.Fatalf("merge: %v %v", merged, err)
	}
	bytes, err := local.GetMonthlyUsage(ctx, merged.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes != 20 {
		t.Errorf("merged account bandwidth = %d, want 20", bytes)
	}
	out, err := ledger.Export(ctx, &meterpb.ExportRequest{Owner: merged.ID})
	if err != nil {
		t.Fatal(err)
	}
	if out.OwnerUsage.AdmittedRequests != 2 || out.OwnerUsage.TotalBytes != 20 {
		t.Errorf("merged usage: requests=%d bytes=%d, want 2 and 20", out.OwnerUsage.AdmittedRequests, out.OwnerUsage.TotalBytes)
	}
	resolved, err := ledger.Resolve(ctx, &meterpb.ResolveRequest{Owner: merged.ID, Endpoint: "merged-api", TokenSha256: token[:]})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Id != grant.Id || resolved.Owner != merged.ID || resolved.MonthlyRequests != 1 || resolved.MonthlyBytes != 10 || resolved.RequestsPerMinute != 1 {
		t.Errorf("grant orphaned: resolved %q, want %q", resolved.Id, grant.Id)
	}
	listed, err := ledger.ListGrants(ctx, &meterpb.ListGrantsRequest{Owner: merged.ID, Endpoint: "merged-api"})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Grants) != 1 {
		t.Errorf("merged owner lists %d grants, want 1", len(listed.Grants))
	}
	for _, event := range out.Events {
		if event.Owner != merged.ID {
			t.Errorf("serialized event owner = %s", event.Owner)
		}
	}
	// In-flight events continue charging after their serialized owner moves.
	if _, err := ledger.Charge(ctx, &meterpb.ChargeRequest{RequestId: id, RequestBytes: 10}); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Finish(ctx, &meterpb.Event{RequestId: id, Status: 200}); err != nil {
		t.Fatal(err)
	}
	// A delayed old-UUID accounting write must reach the surviving account.
	if err := local.RecordUsage(ctx, old.ID, 1); err != nil {
		t.Fatal(err)
	}
	if used, err := local.GetMonthlyUsage(ctx, merged.ID); err != nil || used != 21 {
		t.Errorf("delayed accounting = %d, %v", used, err)
	}
	if account, err := local.GetAccount(ctx, old.ID); err != nil || account == nil || account.ID != merged.ID {
		t.Errorf("obsolete UUID did not resolve: %v %v", account, err)
	}
	if _, err := ledger.RevokeGrant(ctx, &meterpb.Grant{Owner: merged.ID, Endpoint: "merged-api", Id: grant.Id}); err != nil {
		t.Errorf("merged owner cannot revoke its grant: %v", err)
	}
	d, err := ledger.Admit(ctx, &meterpb.Event{RequestId: strings.Repeat("2", 32), Owner: old.ID, Endpoint: "merged-api", Caller: "anonymous", AuthMethod: "none", Allowed: true})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Error("merge reset exhausted owner budgets: admitted another request")
	}
	t.Run("atomic", func(t *testing.T) {
		third, err := local.FindOrCreateByEmails(ctx, []string{"third@example.com"}, "magic_link")
		if err != nil {
			t.Fatal(err)
		}
		if err := local.RecordUsage(ctx, third.ID, 9); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO meter_events(id,owner,endpoint,month,finished,data) VALUES(?,?,?,?,1,?)`, strings.Repeat("4", 32), third.ID, "broken", time.Now().UTC().Format("2006-01"), []byte("{")); err != nil {
			t.Fatal(err)
		}
		if _, err := local.FindOrCreateByEmails(ctx, []string{third.PrimaryEmail, merged.PrimaryEmail}, "github"); err == nil {
			t.Fatal("merge accepted malformed accounting")
		}
		if account, err := local.GetAccountByEmail(ctx, third.PrimaryEmail); err != nil || account == nil || account.ID != third.ID {
			t.Errorf("failed merge moved emails: %v %v", account, err)
		}
		if used, err := local.GetMonthlyUsage(ctx, third.ID); err != nil || used != 9 {
			t.Errorf("failed merge moved usage: %d %v", used, err)
		}
		if used, err := local.GetMonthlyUsage(ctx, merged.ID); err != nil || used != 21 {
			t.Errorf("failed merge changed survivor usage: %d %v", used, err)
		}
	})

}

func TestMergedHostRemainsUsable(t *testing.T) {
	s := hostFixture(t)
	token := createTestJWT("owner@example.com", s.cfg.JWTSecret)
	if w := hostRequest(t, s, "POST", token, fixtureManifest); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	owner, err := s.hostAccount(token, false)
	if err != nil {
		t.Fatal(err)
	}
	p := securityProxy(s.storage)
	p.config, p.Domain, p.tunnelServer = s.cfg, s.cfg.Domain, s
	conn, _ := securityEndpoint(p, "gpu-http", owner.PrimaryEmail, owner.ID, []string{owner.PrimaryEmail}, false)
	conn.HostID = "gpu-box"
	survivor, err := s.accounts.FindOrCreateByEmails([]string{"survivor@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.accounts.UpdatePlan(survivor.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	merged, err := s.accounts.FindOrCreateByEmails([]string{owner.PrimaryEmail, survivor.PrimaryEmail}, "github")
	if err != nil || merged.ID != survivor.ID {
		t.Fatalf("merge: %v %v", merged, err)
	}
	w := hostRequest(t, s, "GET", token, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"online":true`) {
		t.Fatalf("host inventory: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest("GET", "https://gpu-http.host.test/", nil)
	r.Header.Set("Tunn-Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("host reports online but returns %d after merge; live UUID=%s surviving UUID=%s: %s", w.Code, conn.AccountID, merged.ID, w.Body.String())
	}
}

func TestLiveBillingUpdatesQuota(t *testing.T) {
	for _, transition := range []struct {
		from, to string
		want     int
	}{{"free", "pro", 200}, {"pro", "free", 429}} {
		t.Run(transition.from+"-to-"+transition.to, func(t *testing.T) {
			ctx := context.Background()
			db, err := store.InitForTest()
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			defer db.Close()
			local := storage.NewLocalStorage(db)
			acc, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.com"}, "github")
			if err != nil {
				t.Fatal(err)
			}
			if err := local.UpdatePlan(ctx, acc.ID, transition.from); err != nil {
				t.Fatal(err)
			}
			if err := local.RecordUsage(ctx, acc.ID, FreeQuotaBytes+1); err != nil {
				t.Fatal(err)
			}
			p, tunnel, _, _ := meteringRelay(t, false, "ok")
			p.storage, tunnel.AccountID, tunnel.Plan = local, acc.ID, transition.from
			if transition.to == "pro" {
				object, _ := json.Marshal(StripeCheckoutSession{ID: "cs_local", CustomerEmail: acc.PrimaryEmail, Mode: "subscription", Status: "complete"})
				if err := p.handleCheckoutCompleted(ctx, StripeEvent{Type: "checkout.session.completed", Data: StripeEventData{Object: object}}); err != nil {
					t.Fatal(err)
				}
			} else {
				p.config.StripeSecretKey = "local-fixture-key"
				previous := http.DefaultClient
				http.DefaultClient = &http.Client{Transport: billingFixtureTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.String() != "https://api.stripe.com/v1/customers/cus_local" || r.Method != "GET" {
						return nil, fmt.Errorf("unexpected provider fixture request")
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"email":"owner@example.com"}`)), Header: make(http.Header)}, nil
				})}
				defer func() { http.DefaultClient = previous }()
				object, _ := json.Marshal(StripeSubscription{ID: "sub_local", Customer: "cus_local", Status: "canceled"})
				if err := p.handleSubscriptionDeleted(ctx, StripeEvent{Type: "customer.subscription.deleted", Data: StripeEventData{Object: object}}); err != nil {
					t.Fatal(err)
				}
			}
			updated, err := local.GetAccount(ctx, acc.ID)
			if err != nil || updated.Plan != transition.to {
				t.Fatalf("plan update: %v %v", updated, err)
			}
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, relayRequest(relayJWT(t, p, acc.PrimaryEmail), ""))
			if w.Code != transition.want {
				t.Fatalf("stored plan=%s live plan=%s: HTTP %d, want %d: %s", updated.Plan, tunnel.Plan, w.Code, transition.want, w.Body.String())
			}
		})
	}
}

func TestApplicationCannotReplacePlatformCookie(t *testing.T) {
	for _, path := range []string{"buffered", "streaming", "websocket"} {
		t.Run(path, func(t *testing.T) {
			p, tunnel, _, stream := meteringRelay(t, path == "streaming", "")
			tunnel.AllowedEmails = nil
			if path == "websocket" {
				tunnel.Capabilities = map[string]bool{common.CapabilityWebSocketV1: true}
			}
			victim := securityCookie(t, p, "victim@example.com")
			attacker := securityCookie(t, p, "attacker@example.com")
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			platform, _ := url.Parse("https://tunn.test/")
			endpoint, _ := url.Parse("https://api.tunn.test/")
			jar.SetCookies(platform, []*http.Cookie{victim})
			stream.hook = func(msg *pb.TunnelMessage) error {
				headers := map[string]string{"sEt-CoOkIe": attacker.String() + ", app_cookie=keep; Expires=Wed, 21 Oct 2037 07:28:00 GMT, tunn_future=bad; Path=/, __Host-tunn_oauth=bad; Path=/; Secure, __Secure-tunn_future=bad; Path=/; Secure"}
				if request := msg.GetHttpRequest(); request != nil {
					tunnel.pendingMu.RLock()
					ch := tunnel.pendingRequests[request.ConnectionId]
					tunnel.pendingMu.RUnlock()
					ch <- &pb.HttpResponse{ConnectionId: request.ConnectionId, StatusCode: 200, Headers: headers}
				}
				if open := msg.GetConnectionOpen(); open != nil && path == "websocket" {
					headers["Upgrade"] = "websocket"
					headers["Connection"] = "Upgrade"
					headers["Sec-WebSocket-Accept"] = common.WebSocketAccept("dGhlIHNhbXBsZSBub25jZQ==")
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 101, Headers: headers}}}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId}}})
				}
				if end := msg.GetConnectionHalfClose(); end != nil && path == "streaming" {
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: end.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 200, Headers: headers}}}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: end.ConnectionId}}})
				}
				return nil
			}
			r := httptest.NewRequest("GET", endpoint.String(), nil)
			for _, cookie := range jar.Cookies(endpoint) {
				r.AddCookie(cookie)
			}
			var response *http.Response
			if path == "websocket" {
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Sec-WebSocket-Version", "13")
				r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				remote, local := net.Pipe()
				defer remote.Close()
				defer local.Close()
				_ = remote.SetDeadline(time.Now().Add(time.Second))
				done := make(chan struct{})
				go func() {
					defer close(done)
					p.createHandler().ServeHTTP(cookieFixtureHijacker{httptest.NewRecorder(), local}, r)
				}()
				response, err = http.ReadResponse(bufio.NewReader(remote), r)
				_ = remote.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("fixture failed to stop")
				}
				if err != nil || response.StatusCode != 101 {
					t.Fatalf("upgrade fixture: %v %v", response, err)
				}
			} else {
				w := httptest.NewRecorder()
				p.createHandler().ServeHTTP(w, r)
				response = w.Result()
				if response.StatusCode != 200 {
					t.Fatalf("response fixture: %d", response.StatusCode)
				}
			}
			cookies := response.Cookies()
			if len(cookies) != 1 || cookies[0].Name != "app_cookie" || cookies[0].Value != "keep" || cookies[0].Expires.Year() != 2037 {
				t.Errorf("application response cookies = %v, want only the application cookie with its expiry", cookies)
			}
			jar.SetCookies(endpoint, cookies)
			next := httptest.NewRequest("GET", platform.String()+"account", nil)
			for _, cookie := range jar.Cookies(platform) {
				next.AddCookie(cookie)
			}
			email, ok := p.getAuthFromCookie(next)
			if !ok || email != "victim@example.com" {
				t.Fatalf("application response replaced platform login: identity=%s authenticated=%v", email, ok)
			}
		})
	}
}

type billingFixtureTransport func(*http.Request) (*http.Response, error)

func (f billingFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type cookieFixtureHijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w cookieFixtureHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}
