package host

// Regression tests adapted from the read-only security security.
// All network provider responses are fixtures, and all databases are in memory.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type securityStream struct {
	mockTunnelStream
	onSend func(*pb.TunnelMessage) error
}

func (s *securityStream) Send(m *pb.TunnelMessage) error {
	if s.onSend != nil {
		return s.onSend(m)
	}
	return s.mockTunnelStream.Send(m)
}

func securityConfig() *config.Config {
	return &config.Config{Environment: config.EnvProd, Domain: "tunn.test", PublicAddr: "tunn.test", JWTSecret: "security-local-fixture-key", WellKnownKey: "security-key", GitHubClientID: "fixture-client"}
}

func securityDB(t *testing.T) *storage.LocalStorage {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return storage.NewLocalStorage(db)
}

func securityProxy(s storage.Storage) *ProxyServer {
	cfg := securityConfig()
	return &ProxyServer{Domain: cfg.Domain, config: cfg, storage: s, tunnelServer: NewTunnelServer(cfg, nil, nil, s), quotaCache: NewQuotaCache(time.Minute), usageBuffer: NewUsageBuffer(), tunnelCache: map[string]string{}, deviceCodeRateByIP: map[string][]time.Time{}}
}

func securityReplicaStorage(t *testing.T, local *storage.LocalStorage) *storage.ProxyStorage {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	internalv1.RegisterLoginNodeDBServer(server, NewLoginNodeDBServer(local))
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///security-login-node", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); server.Stop(); _ = listener.Close() })
	s := storage.NewProxyStorage()
	s.SetConnection(conn)
	return s
}

func securityCookie(t *testing.T, p *ProxyServer, email string) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	if err := p.setAuthCookie(w, email); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies()[0]
}

// Return a minimal successful publisher response while capturing ingress
// metadata. Responses are injected into the actual per-tunnel pending maps.
func securityEndpoint(p *ProxyServer, name, owner, accountID string, allowed []string, streaming bool) (*TunnelConnection, *map[string]string) {
	var captured map[string]string
	tunnel := &TunnelConnection{TunnelID: name, CreatorEmail: owner, AccountID: accountID, AllowedEmails: allowed, Plan: "free", pendingRequests: map[string]chan *pb.HttpResponse{}, Capabilities: map[string]bool{}}
	if streaming {
		tunnel.Capabilities[common.CapabilityHTTPStreamV1] = true
	}
	tunnel.Stream = &securityStream{onSend: func(m *pb.TunnelMessage) error {
		if req := m.GetHttpRequest(); req != nil {
			captured = req.Headers
			tunnel.pendingRequests[req.ConnectionId] <- &pb.HttpResponse{ConnectionId: req.ConnectionId, StatusCode: 200, Body: []byte("fixture")}
		}
		if open := m.GetConnectionOpen(); open != nil {
			captured = open.HttpRequest.Headers
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 200}}}})
			tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId}}})
		}
		return nil
	}}
	p.tunnelServer.tunnels[name] = tunnel
	return tunnel, &captured
}

func securityRegister(t *testing.T, server *TunnelServer, name, token string) *pb.RegisterResponse {
	t.Helper()
	stream := &mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}
	stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: name, TunnelKey: server.cfg.WellKnownKey, AuthToken: token, TargetUrl: "http://127.0.0.1:1"}}}
	close(stream.recvQueue)
	_ = server.EstablishTunnel(stream)
	if len(stream.sentMsgs) == 0 || stream.sentMsgs[0].GetRegisterResponse() == nil {
		t.Fatal("no registration reply")
	}
	return stream.sentMsgs[0].GetRegisterResponse()
}

func TestSecuritySessionCookieDoesNotReachPublisher(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprintf("streaming=%v", streaming), func(t *testing.T) {
			p := securityProxy(storage.NewProxyStorage())
			_, headers := securityEndpoint(p, "attacker", "", "", nil, streaming)
			cookie := securityCookie(t, p, "victim@example.test")
			req := httptest.NewRequest("GET", "https://attacker.tunn.test/", nil)
			req.AddCookie(cookie)
			req.AddCookie(&http.Cookie{Name: "app_cookie", Value: "preserve-me"})
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, req)
			if w.Code != 200 {
				t.Fatalf("forwarding precondition: %d", w.Code)
			}
			forwarded := (*headers)["Cookie"]
			if strings.Contains(forwarded, cookie.Value) {
				// Show the leaked value is a usable identity on a second tenant.
				securityEndpoint(p, "victim", "victim@example.test", "", []string{"victim@example.test"}, false)
				replay := httptest.NewRequest("GET", "https://victim.tunn.test/", nil)
				replay.Header.Set("Cookie", forwarded)
				email, ok := p.getAuthFromCookie(replay)
				victimResponse := httptest.NewRecorder()
				p.createHandler().ServeHTTP(victimResponse, replay)
				t.Errorf("publisher received the domain auth cookie; replay authenticates=%v as %q and reaches private victim endpoint with status=%d", ok, email, victimResponse.Code)
			}
		})
	}
}

func TestSecurityConsumedMagicLinkCannotAuthenticateOtherPaths(t *testing.T) {
	s := securityDB(t)
	p := securityProxy(s)
	token, err := p.generateMagicLinkToken("victim@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.verifyMagicLinkToken(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if _, err := p.verifyMagicLinkToken(context.Background(), token); err == nil {
		t.Fatal("precondition: verification endpoint did not reject replay")
	}
	t.Run("cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://tunn.test/account", nil)
		req.AddCookie(&http.Cookie{Name: authCookieName, Value: token})
		if email, ok := p.getAuthFromCookie(req); ok {
			t.Errorf("consumed magic-link JWT accepted as browser identity %q", email)
		}
	})
	t.Run("private_endpoint_bearer", func(t *testing.T) {
		securityEndpoint(p, "victim", "victim@example.test", "", []string{"victim@example.test"}, false)
		req := httptest.NewRequest("POST", "https://victim.tunn.test/mcp", nil)
		req.Header.Set("Tunn-Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("consumed magic-link JWT was not rejected as unauthorized: %d", w.Code)
		}
	})
	t.Run("publisher_registration", func(t *testing.T) {
		if response := securityRegister(t, p.tunnelServer, "replay", token); response.Success {
			t.Error("consumed magic-link JWT registered a new publisher as victim")
		}
	})
}

func TestSecurityOverQuotaAccountIsBlocked(t *testing.T) {
	s := securityDB(t)
	p := securityProxy(s)
	account, err := s.FindOrCreateByEmails(context.Background(), []string{"owner@example.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RecordUsage(context.Background(), account.ID, FreeQuotaBytes+1); err != nil {
		t.Fatal(err)
	}
	if p.CheckQuota(context.Background(), account.ID, "free") {
		t.Fatal("precondition: account UUID quota check allowed exhausted account")
	}
	securityEndpoint(p, "quota", account.PrimaryEmail, account.ID, nil, false)
	req := httptest.NewRequest("GET", "https://quota.tunn.test/", nil)
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, req)
	if w.Code != 429 {
		usage, _ := s.GetMonthlyUsage(context.Background(), account.ID)
		t.Errorf("over-quota account forwarded with status=%d, UUID usage=%d", w.Code, usage)
	}
}

func TestSecurityReservedSubdomainIsEnforcedOnReplica(t *testing.T) {
	s := securityDB(t)
	ctx := context.Background()
	owner, err := s.FindOrCreateByEmails(ctx, []string{"owner@example.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdatePlan(ctx, owner.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if err := s.AccountStore().ReserveSubdomain(owner.ID, "reserved-agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindOrCreateByEmails(ctx, []string{"attacker@example.test"}, "github"); err != nil {
		t.Fatal(err)
	}
	p := securityProxy(s)
	attackerToken, err := p.generateJWT("attacker@example.test")
	if err != nil {
		t.Fatal(err)
	}
	// Login node has an AccountStore; replica does not. Both use the same
	// Storage interface and registry; there is no reservation RPC in it.
	login := NewTunnelServer(p.config, nil, s.AccountStore(), s)
	if response := securityRegister(t, login, "reserved-agent", attackerToken); response.Success {
		t.Fatal("precondition: login node failed to reject non-owner")
	}
	replica := NewTunnelServer(p.config, nil, nil, securityReplicaStorage(t, s))
	if response := securityRegister(t, replica, "reserved-agent", attackerToken); response.Success {
		t.Error("non-owner claimed another account's reserved subdomain on replica")
	}
	ownerToken, err := p.generateJWT(owner.PrimaryEmail)
	if err != nil {
		t.Fatal(err)
	}
	if response := securityRegister(t, replica, "reserved-agent", ownerToken); !response.Success {
		t.Fatalf("replica denied reservation owner: %s", response.ErrorMessage)
	}
	if response := securityRegister(t, replica, "replica-claim", ownerToken); !response.Success {
		t.Fatalf("replica denied Pro auto-claim: %s", response.ErrorMessage)
	}
	if ownerID, err := s.AccountStore().GetSubdomainOwner("replica-claim"); err != nil || ownerID != owner.ID {
		t.Fatalf("replica auto-claim owner = %q, error = %v", ownerID, err)
	}
}

type securityRegistrationFailure struct{ storage.Storage }

func (s securityRegistrationFailure) RegisterTunnel(context.Context, string, string, string) (*storage.TunnelRegistration, error) {
	return nil, errors.New("fixture registry failure")
}

func TestSecurityRegistrationFailureDoesNotBypassOwnership(t *testing.T) {
	local := securityDB(t)
	if _, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.test"}, "github"); err != nil {
		t.Fatal(err)
	}
	p := securityProxy(securityRegistrationFailure{local})
	token, err := p.generateJWT("owner@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if response := securityRegister(t, p.tunnelServer, "unverified", token); response.Success {
		t.Error("registry RPC error fell back to unverified local ownership")
	}
}

func TestSecurityRegistryOutageDoesNotPermitTenantCollision(t *testing.T) {
	// No login-node connection: the actual unavailable ProxyStorage path.
	p := securityProxy(storage.NewProxyStorage())
	otherNode := NewTunnelServer(p.config, nil, nil, storage.NewProxyStorage())
	ownerToken, _ := p.generateJWT("owner@example.test")
	attackerToken, _ := p.generateJWT("attacker@example.test")
	stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
	stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "same-name", TunnelKey: p.config.WellKnownKey, AuthToken: ownerToken}}}
	close(stream.recvQueue)
	stream.onSend = func(m *pb.TunnelMessage) error {
		response := m.GetRegisterResponse()
		if response == nil || !response.Success {
			return nil // Failing closed during outage satisfies the safety check.
		}
		if conn, exists := p.tunnelServer.GetTunnel("same-name"); !exists || conn.CreatorEmail != "owner@example.test" {
			t.Fatal("precondition: owner tunnel must still be active on first node")
		}
		if response := securityRegister(t, otherNode, "same-name", attackerToken); response.Success {
			t.Error("registry outage allowed two different tenants to publish the same hostname concurrently on different nodes")
		}
		return nil
	}
	if err := p.tunnelServer.EstablishTunnel(stream); err != nil {
		return // Refusing registration while ownership is unknown is safe.
	}
}

func TestSecuritySiblingOriginCannotAuthorizeDevice(t *testing.T) {
	s := securityDB(t)
	p := securityProxy(s)
	code, err := s.CreateDeviceCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"code": {code.UserCode}}
	req := httptest.NewRequest("POST", "https://tunn.test/auth/device/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.tunn.test")
	req.Header.Set("Referer", "https://attacker.tunn.test/")
	req.AddCookie(securityCookie(t, p, "victim@example.test"))
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, req)
	code, err = s.GetDeviceCode(context.Background(), code.Code)
	if err != nil {
		t.Fatal(err)
	}
	if code.Authorized {
		poll := httptest.NewRequest("GET", "https://tunn.test/api/device/token?code="+url.QueryEscape(code.Code), nil)
		pollWriter := httptest.NewRecorder()
		p.createHandler().ServeHTTP(pollWriter, poll)
		t.Errorf("sibling-origin POST authorized device as %q; unauthenticated poll status=%d and minted token=%v", code.Email, pollWriter.Code, strings.Contains(pollWriter.Body.String(), "access_token"))
	}
}

func TestSecurityQuotaUnavailableFailsClosed(t *testing.T) {
	p := securityProxy(storage.NewProxyStorage())
	p.quotaCache.Set("account-uuid", 0)
	if p.CheckQuota(context.Background(), "account-uuid", "free") {
		t.Error("unavailable usage storage allowed traffic using an unverified cache")
	}
}

func TestSecurityPublicPublisherReceivesOnlyApplicationCredentials(t *testing.T) {
	p := securityProxy(storage.NewProxyStorage())
	accountToken, err := p.generateJWT("victim@example.test")
	if err != nil {
		t.Fatal(err)
	}
	magicToken, err := p.generateMagicLinkToken("victim@example.test")
	if err != nil {
		t.Fatal(err)
	}
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": "victim@example.test", "exp": time.Now().Add(-time.Minute).Unix(),
	}).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, streaming := range []bool{false, true} {
		for _, credential := range []string{accountToken, magicToken, expired, "tunn_ep_another-endpoint"} {
			t.Run(fmt.Sprintf("streaming=%v/token=%x", streaming, sha256.Sum256([]byte(credential))), func(t *testing.T) {
				_, headers := securityEndpoint(p, "publisher", "", "", nil, streaming)
				req := httptest.NewRequest("GET", "https://publisher.tunn.test/", nil)
				req.Header.Set("Authorization", "Bearer "+credential)
				req.Header.Set("Tunn-Authorization", "Bearer "+credential)
				req.Header.Add("Cookie", "tunn_auth=private; app=keep")
				req.Header.Add("Cookie", "tunn_session=private; tunn_csrf=private; __Host-tunn_oauth=private; app2=keep")
				w := httptest.NewRecorder()
				p.createHandler().ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("forwarding status = %d", w.Code)
				}
				if (*headers)["Authorization"] != "" || (*headers)["Tunn-Authorization"] != "" || (*headers)["Cookie"] != "app=keep; app2=keep" {
					t.Fatalf("publisher received relay credentials: %v", *headers)
				}
				if req.Header.Get("Authorization") == "" || len(req.Header.Values("Cookie")) != 2 {
					t.Fatal("sanitizing mutated the original request")
				}
			})
		}
	}
}

func TestSecurityMagicLinkConsumptionSurvivesStorageRecreation(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	p := securityProxy(storage.NewLocalStorage(db))
	token, err := p.generateMagicLinkToken("victim@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.verifyMagicLinkToken(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	p.storage = storage.NewLocalStorage(db)
	if _, err := p.verifyMagicLinkToken(context.Background(), token); err == nil {
		t.Error("recreating login storage made a consumed link usable again")
	}
}

func TestSecurityMagicLinkConsumptionIsAtomicAndRejectsExpiredClaims(t *testing.T) {
	s := securityDB(t)
	ctx := context.Background()
	expiry := time.Now().Add(time.Minute)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			ok, err := s.MarkMagicTokenUsed(ctx, "concurrent-token", expiry)
			if err != nil {
				t.Error(err)
			} else if ok {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Errorf("accepted concurrent token %d times, want 1", accepted.Load())
	}
	if ok, err := s.MarkMagicTokenUsed(ctx, "expired-token", time.Now().Add(-time.Second)); err == nil && ok {
		t.Error("storage consumed an expired token")
	}
	if ok, err := s.MarkMagicTokenUsed(ctx, "", expiry); err == nil && ok {
		t.Error("storage consumed an empty token ID")
	}
}
