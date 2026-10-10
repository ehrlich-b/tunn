package host

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
)

func TestIntegrationAccountUUIDUnifiesQuotaGrantsAndAliasBudgets(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, replica := range []bool{false, true} {
			t.Run(fmt.Sprintf("streaming=%v/replica=%v", streaming, replica), func(t *testing.T) {
				ctx := context.Background()
				db, err := store.InitForTest()
				if err != nil {
					t.Fatal(err)
				}
				db.SetMaxOpenConns(1)
				t.Cleanup(func() { _ = db.Close() })
				local := storage.NewLocalStorage(db)
				account, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.com", "alias@example.com"}, "github")
				if err != nil {
					t.Fatal(err)
				}
				ledger, err := metering.New(db, metering.WithOwnerBudgets(2, 100))
				if err != nil {
					t.Fatal(err)
				}
				p, tunnel, _, stream := meteringRelay(t, streaming, "ok")
				p.storage, p.meter, tunnel.AccountID = local, ledger, account.ID
				if replica {
					p.storage = securityReplicaStorage(t, local)
				}
				const token = "tunn_gr_alias-integration"
				digest := sha256.Sum256([]byte(token))
				// Use the actual owner API, rather than inserting a grant under an assumed identity.
				grantJSONBytes, err := json.Marshal(&meterpb.Grant{TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), MonthlyRequests: 10, MonthlyBytes: 100})
				if err != nil {
					t.Fatal(err)
				}
				apiCall := func(method, path, email, body string) *httptest.ResponseRecorder {
					r := httptest.NewRequest(method, "https://tunn.test"+path, strings.NewReader(body))
					r.Header.Set("Authorization", "Bearer "+relayJWT(t, p, email))
					w := httptest.NewRecorder()
					p.createHandler().ServeHTTP(w, r)
					return w
				}
				created := apiCall("POST", "/api/endpoints/api/grants", "alias@example.com", string(grantJSONBytes))
				var grant meterpb.Grant
				if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &grant) != nil || grant.Owner != account.ID {
					t.Fatalf("alias grant owner=%q response=%d %s", grant.Owner, created.Code, created.Body.String())
				}
				first := httptest.NewRecorder()
				p.createHandler().ServeHTTP(first, relayRequest(token, "data"))
				if first.Code != 200 {
					t.Fatalf("grant admission=%d %s", first.Code, first.Body.String())
				}
				// The same account publishes a second endpoint under another verified email.
				aliasProxy, aliasTunnel, _, aliasStream := meteringRelay(t, streaming, "ok")
				aliasProxy.storage, aliasProxy.meter = p.storage, ledger
				aliasTunnel.TunnelID, aliasTunnel.CreatorEmail, aliasTunnel.AccountID = "alias-endpoint", "alias@example.com", account.ID
				aliasProxy.tunnelServer.tunnels[aliasTunnel.TunnelID] = aliasTunnel
				secondRequest := relayRequest(relayJWT(t, p, "alias@example.com"), "data")
				secondRequest.Host = "alias-endpoint.tunn.test"
				second := httptest.NewRecorder()
				aliasProxy.createHandler().ServeHTTP(second, secondRequest)
				if second.Code != 200 {
					t.Fatalf("alias admission=%d %s", second.Code, second.Body.String())
				}
				messageCount := func() int {
					stream.mu.Lock()
					defer stream.mu.Unlock()
					aliasStream.mu.Lock()
					defer aliasStream.mu.Unlock()
					return len(stream.sentMsgs) + len(aliasStream.sentMsgs)
				}
				before := messageCount()
				denied := httptest.NewRecorder()
				p.createHandler().ServeHTTP(denied, relayRequest(token, "data"))
				if denied.Code != 429 || denied.Header().Get("Tunn-Limit-Reason") != "owner_request_budget" || messageCount() != before {
					t.Fatalf("alias bypassed shared owner cap: %d %s", denied.Code, denied.Body.String())
				}
				for _, email := range []string{"owner@example.com", "alias@example.com"} {
					w := apiCall("GET", "/api/usage", email, "")
					var out meterpb.ExportResponse
					if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.OwnerUsage == nil || out.OwnerUsage.Owner != account.ID || out.OwnerUsage.AdmittedRequests != 2 || out.OwnerUsage.TotalBytes != 12 {
						t.Fatalf("alias usage=%d %s", w.Code, w.Body.String())
					}
				}
				usage, err := local.GetMonthlyUsage(ctx, account.ID)
				if err != nil || usage != 12 {
					t.Fatalf("UUID bandwidth usage=%d err=%v", usage, err)
				}
				// Account quota runs before owner/grant admission and uses the same UUID.
				if err := local.RecordUsage(ctx, account.ID, FreeQuotaBytes-usage); err != nil {
					t.Fatal(err)
				}
				assertClosed := func(want int) {
					w := httptest.NewRecorder()
					p.createHandler().ServeHTTP(w, relayRequest(token, "data"))
					if w.Code != want || messageCount() != before {
						t.Fatalf("failed closed=%d want=%d messages=%d want=%d", w.Code, want, messageCount(), before)
					}
				}
				assertClosed(429)
				p.quotaCache.Set(account.ID, 0)
				p.storage = securityUsageFailure{Storage: p.storage}
				assertClosed(429)
				p.storage = storage.NewProxyStorage()
				assertClosed(429)
				if w := apiCall("GET", "/api/usage", "alias@example.com", ""); w.Code != 503 {
					t.Fatalf("owner API trusted unavailable identity service: %d", w.Code)
				}
				p.storage = local
				for _, id := range []string{"", account.PrimaryEmail, "unknown-account"} {
					tunnel.AccountID = id
					w := httptest.NewRecorder()
					p.createHandler().ServeHTTP(w, relayRequest(relayJWT(t, p, "owner@example.com"), "data"))
					if w.Code != 429 || messageCount() != before {
						t.Fatalf("unknown account identity %q reached publisher: %d", id, w.Code)
					}
				}
				tunnel.AccountID = account.ID
				p.meter = &metering.Remote{Connection: func() *grpc.ClientConn { return nil }}
				assertClosed(503)
			})
		}
	}
}

func TestIntegrationHTTPGrantsStripPlatformCredentialsAndPreserveApplicationJWTs(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, signingKey := range []bool{false, true} {
			t.Run(fmt.Sprintf("streaming=%v/signing-key=%v", streaming, signingKey), func(t *testing.T) {
				p, tunnel, ledger, stream := meteringRelay(t, streaming, "ok")
				tunnel.AllowedEmails = nil
				appJWT, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "app-user", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("application-signing-key"))
				if err != nil {
					t.Fatal(err)
				}
				if !signingKey {
					p.config.Environment, p.config.JWTSecret = config.EnvProd, ""
				}
				_, grantToken := relayGrant(t, ledger, 10, 100)
				r := relayRequest(grantToken, "")
				r.Header["Authorization"] = []string{"Bearer tunn_ep_revoked", "Bearer " + appJWT, "Bearer tunn_sk_operator"}
				r.Header.Set("Cookie", "tunn_auth=secret; __Host-tunn_csrf=secret; tunn_future=secret; app=kept")
				w := httptest.NewRecorder()
				p.createHandler().ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("application JWT forwarding=%d %s", w.Code, w.Body.String())
				}
				var forwarded map[string]string
				for _, msg := range stream.sentMsgs {
					if req := msg.GetHttpRequest(); req != nil {
						forwarded = req.Headers
					}
					if open := msg.GetConnectionOpen(); open != nil && open.HttpRequest != nil {
						forwarded = open.HttpRequest.Headers
					}
				}
				if forwarded == nil || forwarded["Authorization"] != "Bearer "+appJWT || forwarded["Cookie"] != "app=kept" || forwarded["Tunn-Authorization"] != "" {
					t.Fatalf("forwarded credentials=%v", forwarded)
				}
				if len(r.Header.Values("Authorization")) != 3 || r.Header.Get("Tunn-Authorization") != "Bearer "+grantToken {
					t.Fatal("credential stripping changed the original request")
				}
				// Consuming a platform identity must also preserve other application
				// values in the same header, regardless of bearer-field preference.
				if signingKey {
					tunnel.AllowedEmails = []string{"owner@example.com"}
					for _, platformHeader := range []string{"Authorization", "Tunn-Authorization"} {
						r := relayRequest("", "")
						identity := "Bearer " + relayJWT(t, p, "owner@example.com")
						if platformHeader == "Tunn-Authorization" {
							r.Header.Set(platformHeader, identity)
						}
						r.Header["Authorization"] = []string{identity, "Bearer " + appJWT}
						w := httptest.NewRecorder()
						p.createHandler().ServeHTTP(w, r)
						if w.Code != 200 {
							t.Fatalf("mixed bearer values=%d %s", w.Code, w.Body.String())
						}
						last := stream.sentMsgs[len(stream.sentMsgs)-1]
						if streaming {
							for _, msg := range stream.sentMsgs {
								if open := msg.GetConnectionOpen(); open != nil {
									forwarded = open.HttpRequest.Headers
								}
							}
						} else {
							forwarded = last.GetHttpRequest().Headers
						}
						if forwarded["Authorization"] != "Bearer "+appJWT || forwarded["Tunn-Authorization"] != "" {
							t.Fatalf("consumed identity stripped application credentials: %v", forwarded)
						}
					}
				}
			})
		}
	}
}

func TestWebSocketIntegrationSelfHostedApplicationJWTAndPlatformCredentials(t *testing.T) {
	for _, signingKey := range []bool{false, true} {
		t.Run(fmt.Sprintf("signing-key=%v", signingKey), func(t *testing.T) {
			s := startWebSocketStack(t, func(p *client.ServeClient) { p.RequireUpstreamAuth = true })
			if !signingKey {
				s.proxy.config.Environment, s.proxy.config.JWTSecret = config.EnvProd, ""
			}
			appJWT, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "app-user", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("application-signing-key"))
			if err != nil {
				t.Fatal(err)
			}
			conn, reader := mustWebSocket(t, s, "/headers", http.Header{
				"Authorization":      {"Bearer " + appJWT},
				"Tunn-Authorization": {"Bearer tunn_ep_revoked"},
				"Cookie":             {"tunn_auth=secret; __Host-tunn_csrf=secret; app=kept"},
			})
			frame, err := fixtureReadFrame(reader, false)
			if err != nil {
				t.Fatal(err)
			}
			var headers map[string]string
			if json.Unmarshal(frame.payload, &headers) != nil || headers["auth"] != "Bearer "+appJWT || headers["tunnAuth"] != "" || headers["cookie"] != "app=kept" {
				t.Fatalf("WebSocket credentials=%v", headers)
			}
			_, _ = conn.Write(fixtureFrame(8, true, true, []byte{3, 232}))
			expectWireFrame(t, reader, 8, []byte{3, 232})
			_ = conn.Close()
			waitWebSocketsClosed(t, s)
			before := s.fixture.hits.Load()
			cases := []struct {
				token  string
				status int
			}{{"tunn_ep_revoked", 401}, {"tunn_sk_operator", 401}, {"tunn_gr_revoked", 503}}
			if signingKey {
				expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"email": "owner@example.com", "exp": time.Now().Add(-time.Minute).Unix()}).SignedString(s.proxy.getJWTSigningKey())
				if err != nil {
					t.Fatal(err)
				}
				cases = append(cases, struct {
					token  string
					status int
				}{expired, 401})
			}
			for _, tc := range cases {
				conn, _, response, err := s.dial("/echo", http.Header{"Authorization": {"Bearer " + tc.token}}, nil)
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.Close()
				if response.StatusCode != tc.status || s.fixture.hits.Load() != before {
					t.Fatalf("platform credential satisfied upstream auth: %d hits=%d", response.StatusCode, s.fixture.hits.Load())
				}
			}
		})
	}
}

func TestWebSocketIntegrationMeteringAndAccountQuota(t *testing.T) {
	s := startWebSocketStack(t, nil)
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	local := storage.NewLocalStorage(db)
	ctx := context.Background()
	account, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := metering.New(db, metering.WithOwnerBudgets(1, 100))
	if err != nil {
		t.Fatal(err)
	}
	s.proxy.storage, s.proxy.meter, s.proxy.usageBuffer = local, ledger, NewUsageBuffer()
	s.tunnel.AccountID, s.tunnel.CreatorEmail, s.tunnel.accountQuotaExempt = account.ID, account.PrimaryEmail, false
	const grantToken = "tunn_gr_websocket-integration"
	digest := sha256.Sum256([]byte(grantToken))
	if _, err := ledger.CreateGrant(ctx, &meterpb.Grant{Owner: account.ID, Endpoint: s.tunnel.TunnelID, TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	// A body-byte grant cannot authorize an unmetered WebSocket data channel.
	conn, _, denied, err := s.dial("/echo", http.Header{"Tunn-Authorization": {"Bearer " + grantToken}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if denied.StatusCode != 403 || s.fixture.hits.Load() != 0 {
		t.Fatalf("HTTP grant authorized WebSocket frames: status=%d hits=%d", denied.StatusCode, s.fixture.hits.Load())
	}
	conn, reader, response, err := s.dial("/echo", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 || response.Header.Get("Tunn-Request-ID") == "" || response.Header.Get("Tunn-Requests-Remaining") != "0" {
		t.Fatalf("upgrade admission=%d %v", response.StatusCode, response.Header)
	}
	input := fixtureFrame(1, true, true, []byte("payload"))
	_, _ = conn.Write(input)
	expectWireFrame(t, reader, 1, []byte("payload"))
	closeFrame := fixtureFrame(8, true, true, []byte{3, 232})
	_, _ = conn.Write(closeFrame)
	expectWireFrame(t, reader, 8, []byte{3, 232})
	_ = conn.Close()
	wantBytes := int64(len(input) + len(closeFrame) + len(fixtureFrame(1, true, false, []byte("payload"))) + len(fixtureFrame(8, true, false, []byte{3, 232})))
	// Completion follows the close reply asynchronously through the real publisher.
	deadline := time.Now().Add(time.Second)
	var out *meterpb.ExportResponse
	for time.Now().Before(deadline) {
		out, err = ledger.Export(ctx, &meterpb.ExportRequest{Owner: account.ID})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Events) == 2 && out.Events[1].Finished {
			break
		}
		time.Sleep(time.Millisecond)
	}
	usage, err := local.GetMonthlyUsage(ctx, account.ID)
	if err != nil || usage != wantBytes || len(out.Events) != 2 || !out.Events[1].Finished || out.Events[1].Status != 101 || !out.Events[1].Forwarded || out.OwnerUsage.AdmittedRequests != 1 || out.OwnerUsage.TotalBytes != wantBytes {
		t.Fatalf("upgrade usage=%d want=%d err=%v ledger=%v", usage, wantBytes, err, out)
	}
	before := s.fixture.hits.Load()
	conn, _, denied, err = s.dial("/echo", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if denied.StatusCode != 429 || denied.Header.Get("Tunn-Limit-Reason") != "owner_request_budget" || s.fixture.hits.Load() != before {
		t.Fatalf("WebSocket bypassed owner cap: %d %v", denied.StatusCode, denied.Header)
	}
	s.proxy.quotaCache.Set(account.ID, 0)
	s.proxy.storage = storage.NewProxyStorage()
	conn, _, denied, err = s.dial("/echo", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if denied.StatusCode != 429 || s.fixture.hits.Load() != before {
		t.Fatalf("quota outage authorized upgrade: %d", denied.StatusCode)
	}
}
