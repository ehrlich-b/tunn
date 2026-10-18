package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/sshfront"
	"github.com/ehrlich-b/tunn/internal/store"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/ssh"
)

var prodAuthPrincipals = []string{
	"anonymous", "owner-jwt", "other-jwt", "alias-jwt", "owner-cookie",
	"other-cookie", "endpoint-token", "consumer-grant", "mcp-oauth", "login-proof", "expired-jwt",
}

type prodAuthRoute struct {
	method, path, pattern, body string
	want                        [11]int
}

// Columns are prodAuthPrincipals, in that order. Public workflows still require
// their own proof (OAuth code, email link, webhook signature, or CSRF); a 400
// below means account credentials do not substitute for that missing proof.
var prodAuthRoutes = []prodAuthRoute{
	{"GET", "/api/account/tunnels", "/api/account/tunnels", "", [11]int{302, 302, 302, 302, 200, 200, 302, 302, 302, 302, 302}},
	{"GET", "/account/tunnel-alerts", "/account/tunnel-alerts", "", [11]int{302, 302, 302, 302, 200, 302, 302, 302, 302, 302, 302}},
	{"POST", "/account/tunnel-alerts", "/account/tunnel-alerts", "", [11]int{302, 302, 302, 302, 403, 302, 302, 302, 302, 302, 302}},
	{"GET", "/account/emails", "/account/emails", "", [11]int{302, 302, 302, 302, 303, 302, 302, 302, 302, 302, 302}},
	{"POST", "/account/emails", "/account/emails", "", [11]int{302, 302, 302, 302, 403, 302, 302, 302, 302, 302, 302}},
	{"GET", "/api/ip-policy", "/api/ip-policy", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/ip-policy/unknown", "/api/ip-policy/", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"PUT", "/api/ip-policy/unknown", "/api/ip-policy/", `{}`, [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"DELETE", "/api/ip-policy/unknown", "/api/ip-policy/", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/account/ip-policy", "/account/ip-policy", "", [11]int{302, 302, 302, 302, 200, 200, 302, 302, 302, 302, 302}},
	{"POST", "/account/ip-policy", "/account/ip-policy", "", [11]int{302, 302, 302, 302, 403, 403, 302, 302, 302, 302, 302}},
	{"GET", "/docs/ip-restrictions", "/docs/", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/auth/domain", "/auth/domain", "", [11]int{400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400}},
	{"GET", "/.well-known/tunn-jwks.json", "/.well-known/tunn-jwks.json", "", [11]int{503, 503, 503, 503, 503, 503, 503, 503, 503, 503, 503}},
	{"GET", "/auth/org/unknown", "/auth/org/", "", [11]int{404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404}},
	{"GET", "/auth/org/unknown/callback", "/auth/org/", "", [11]int{404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404}},
	{"GET", "/auth/google", "/auth/google", "", [11]int{503, 503, 503, 503, 503, 503, 503, 503, 503, 503, 503}},
	{"GET", "/auth/google/callback", "/auth/google/callback", "", [11]int{503, 503, 503, 503, 503, 503, 503, 503, 503, 503, 503}},
	{"GET", "/api/sharing", "/api/sharing", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/sharing/unknown", "/api/sharing/", "", [11]int{401, 400, 400, 400, 401, 401, 401, 401, 401, 401, 401}},
	{"POST", "/api/sharing/unknown", "/api/sharing/", `{"email":"alice@example.com"}`, [11]int{401, 400, 400, 400, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/account/sharing", "/account/sharing", "", [11]int{302, 302, 302, 302, 200, 200, 302, 302, 302, 302, 302}},
	{"POST", "/account/sharing?tunnel=unknown", "/account/sharing", "", [11]int{302, 302, 302, 302, 403, 403, 302, 302, 302, 302, 302}},

	{"GET", "/", "/", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/privacy", "/", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/terms", "/", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/health", "/health", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/healthz", "/healthz", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/readyz", "/readyz", "", [11]int{503, 503, 503, 503, 503, 503, 503, 503, 503, 503, 503}},
	{"GET", "/status", "/status", "", [11]int{503, 503, 503, 503, 503, 503, 503, 503, 503, 503, 503}},
	{"GET", "/status.json", "/status.json", "", [11]int{503, 503, 503, 503, 503, 503, 503, 503, 503, 503, 503}},
	{"HEAD", "/status", "/status", "", [11]int{503, 503, 503, 503, 503, 503, 503, 503, 503, 503, 503}},
	{"POST", "/status.json", "/status.json", "", [11]int{405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405}},
	{"GET", "/dl/examples/mcp/echo.py", "/dl/examples/mcp/echo.py", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"HEAD", "/dl/examples/mcp/echo.py", "/dl/examples/mcp/echo.py", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"POST", "/dl/examples/mcp/echo.py", "/dl/examples/mcp/echo.py", "", [11]int{405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405}},
	{"GET", "/dl/latest.json", "/dl/", "", [11]int{404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404}},
	{"GET", "/install.sh", "/install.sh", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/auth/login", "/auth/login", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/auth/github", "/auth/github", "", [11]int{302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302}},
	{"GET", "/auth/mock", "/auth/mock", "", [11]int{302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302}},
	{"GET", "/auth/callback", "/auth/callback", "", [11]int{400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400}},
	{"POST", "/auth/magic", "/auth/magic", `{"email":"invalid"}`, [11]int{400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400}},
	{"GET", "/auth/verify", "/auth/verify", "", [11]int{400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400}},
	{"GET", "/auth/logout", "/auth/logout", "", [11]int{302, 302, 302, 302, 200, 200, 302, 302, 302, 302, 302}},
	{"POST", "/auth/logout", "/auth/logout", "csrf", [11]int{403, 403, 403, 403, 302, 302, 403, 403, 403, 403, 403}},
	// The owner cookie is UUID-bound; the other cookie is legacy. Inspector
	// writes below omit the session-bound CSRF proof and must be rejected.
	{"GET", "/account/inspect", "/account/inspect", "", [11]int{401, 401, 401, 401, 200, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/inspector/endpoints", "/api/inspector/", "", [11]int{401, 401, 401, 401, 200, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/inspector/tools/requests", "/api/inspector/", "", [11]int{401, 401, 401, 401, 200, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/inspector/tools/requests/1", "/api/inspector/", "", [11]int{401, 401, 401, 401, 404, 401, 401, 401, 401, 401, 401}},
	{"POST", "/api/inspector/tools/requests/1/prepare", "/api/inspector/", "{}", [11]int{401, 401, 401, 401, 403, 401, 401, 401, 401, 401, 401}},
	{"POST", "/api/inspector/tools/requests/1/replay", "/api/inspector/", "{}", [11]int{401, 401, 401, 401, 403, 401, 401, 401, 401, 401, 401}},
	{"GET", "/account", "/account", "", [11]int{302, 302, 302, 302, 200, 200, 302, 302, 302, 302, 302}},
	{"GET", "/account/devices", "/account/devices", "", [11]int{302, 302, 302, 302, 200, 200, 302, 302, 302, 302, 302}},
	// The owner cookie comes from a verified mailbox callback; legacy cookies
	// and publisher/capability credentials cannot replace that account binding.
	{"GET", "/account/app-devices", "/account/app-devices", "", [11]int{302, 302, 302, 302, 200, 302, 302, 302, 302, 302, 302}},
	{"GET", "/pair/app-device", "/pair/app-device", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/api/app-devices", "/api/app-devices", "", [11]int{401, 401, 401, 401, 200, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/app-devices/script", "/api/app-devices/", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"POST", "/api/app-devices/claims", "/api/app-devices/", `{}`, [11]int{400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400}},
	{"POST", "/api/app-devices/invitations", "/api/app-devices/", "", [11]int{401, 401, 401, 401, 403, 401, 401, 401, 401, 401, 401}},
	{"POST", "/account/devices", "/account/devices", "csrf", [11]int{302, 302, 302, 302, 404, 404, 302, 302, 302, 302, 302}},
	{"GET", "/pricing", "/pricing", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/ngrok-alternative", "/ngrok-alternative", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/docs", "/docs", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/docs/mcp-to-claude", "/docs/", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/docs/status", "/docs/", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/docs/docker", "/docs/", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"GET", "/upgrade", "/upgrade", "", [11]int{302, 302, 302, 302, 303, 303, 302, 302, 302, 302, 302}},
	{"GET", "/api/billing/status", "/api/billing/status", "", [11]int{302, 302, 302, 302, 200, 200, 302, 302, 302, 302, 302}},
	{"GET", "/account/mcp", "/account/mcp", "", [11]int{302, 302, 302, 302, 200, 200, 302, 302, 302, 302, 302}},
	{"POST", "/account/mcp?tunnel=tools", "/account/mcp", "csrf", [11]int{302, 302, 302, 302, 303, 303, 302, 302, 302, 302, 302}},
	{"GET", "/api/mcp/clients?tunnel=tools", "/api/mcp/clients", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"DELETE", "/api/mcp/clients?tunnel=tools", "/api/mcp/clients", "", [11]int{401, 204, 204, 204, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"POST", "/oauth/register", "/oauth/", `{"redirect_uris":["https://connector.example/cb"]}`, [11]int{201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 201}},
	{"GET", "/oauth/authorize", "/oauth/", "", [11]int{302, 302, 302, 302, 200, 302, 302, 302, 302, 302, 302}},
	{"POST", "/oauth/authorize", "/oauth/", "consent", [11]int{401, 401, 401, 401, 302, 403, 401, 401, 401, 401, 401}},
	{"POST", "/oauth/token", "/oauth/", "grant_type=authorization_code", [11]int{400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400}},
	{"GET", "/oauth/unknown", "/oauth/", "", [11]int{404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404}},
	{"GET", "/api/hosts", "/api/hosts", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"POST", "/api/hosts", "/api/hosts", `{"machine":"workstation","tunnels":[{"name":"tools","kind":"mcp"}]}`, [11]int{401, 200, 409, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/ssh/keys", "/api/ssh/keys", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"POST", "/api/ssh/keys", "/api/ssh/keys", "key", [11]int{401, 202, 202, 202, 401, 401, 401, 401, 401, 401, 401}},
	{"DELETE", "/api/ssh/keys", "/api/ssh/keys", "", [11]int{401, 200, 404, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/auth/ssh-key", "/auth/ssh-key", "", [11]int{400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400}},
	{"POST", "/api/device/code", "/api/device/code", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"POST", "/api/device/refresh", "/api/device/refresh", "", [11]int{400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400}},
	{"GET", "/api/device/token", "/api/device/token", "", [11]int{400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400}},
	{"GET", "/api/endpoints/unknown/policy", "/api/endpoints/", "", [11]int{401, 404, 404, 404, 401, 401, 401, 401, 401, 401, 401}},
	{"PUT", "/api/endpoints/unknown/policy", "/api/endpoints/", `{}`, [11]int{401, 404, 404, 404, 401, 401, 401, 401, 401, 401, 401}},
	{"DELETE", "/api/endpoints/unknown/policy", "/api/endpoints/", "", [11]int{401, 404, 404, 404, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/endpoints/tools/grants", "/api/endpoints/", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"POST", "/api/endpoints/tools/grants", "/api/endpoints/", "grant", [11]int{401, 201, 403, 201, 401, 401, 401, 401, 401, 401, 401}},
	{"DELETE", "/api/endpoints/tools/grants/", "/api/endpoints/", "", [11]int{401, 204, 404, 204, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/endpoints/tools/usage", "/api/endpoints/", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/usage", "/api/usage", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/grants", "/api/grants", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/api/domains", "/api/domains", "", [11]int{401, 200, 200, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"POST", "/api/domains/publisher", "/api/domains/publisher", `{"name":"tools.apps.example.com"}`, [11]int{401, 200, 403, 200, 401, 401, 401, 401, 401, 401, 401}},
	{"POST", "/api/domains", "/api/domains", `{"name":"work.example.com","tunnel":"tools"}`, [11]int{401, 201, 409, 201, 401, 401, 401, 401, 401, 401, 401}},
	{"POST", "/api/domains/work.example.com/verify", "/api/domains/", "", [11]int{401, 409, 404, 409, 401, 401, 401, 401, 401, 401, 401}},
	{"DELETE", "/api/domains/work.example.com", "/api/domains/", "", [11]int{401, 204, 404, 204, 401, 401, 401, 401, 401, 401, 401}},
	{"POST", "/api/reports", "/api/reports", `{"category":"availability","endpoint":"tools"}`, [11]int{401, 202, 202, 202, 401, 401, 401, 401, 401, 401, 401}},
	{"GET", "/login", "/login", "", [11]int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200}},
	{"POST", "/auth/device/authorize", "/auth/device/authorize", "csrf", [11]int{403, 403, 403, 403, 200, 200, 403, 403, 403, 403, 403}},
	{"POST", "/webhooks/stripe", "/webhooks/stripe", `{}`, [11]int{400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 400}},
}

type prodAuthFixture struct {
	*mcpOAuthFixture
	client               *specMCPClient
	credentials          map[string]string
	grantID, fingerprint string
	publicKey, userCode  string
}

func newProdAuthFixture(t *testing.T) *prodAuthFixture {
	t.Helper()
	f := newMCPOAuthFixture(t)
	db := f.p.mcpOAuth.db
	db.SetMaxOpenConns(1)
	deviceRegistry, deviceErr := newDeviceCredentialStore(db)
	if deviceErr != nil {
		t.Fatal(deviceErr)
	}
	f.p.devices = deviceRegistry
	f.p.appDevices, deviceErr = newAppDeviceStore(db)
	if deviceErr != nil {
		t.Fatal(deviceErr)
	}
	ctx := context.Background()
	if _, err := f.p.storage.FindOrCreateByEmails(ctx, []string{"owner@example.com", "alias@example.net"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.storage.FindOrCreateByEmails(ctx, []string{"other@example.com"}, "test"); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"owner@example.com", "other@example.com"} {
		a, err := f.p.storage.GetAccountByEmail(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.p.storage.UpdatePlan(ctx, a.ID, "pro"); err != nil {
			t.Fatal(err)
		}
	}
	f.p.config.HostModeEnabled, f.p.config.LoginNode = true, true
	f.p.config.StripeWebhookSecret = "offline-webhook-key"
	f.p.tunnelServer.accounts = store.NewAccountStore(db)
	if err := f.p.tunnelServer.EnableHostMode(db); err != nil {
		t.Fatal(err)
	}
	manifest := `{"machine":"workstation","tunnels":[{"name":"tools","kind":"mcp"}]}`
	if w := f.request("POST", "https://tunn.test/api/hosts", manifest, "application/json", relayJWT(t, f.p, "owner@example.com"), nil); w.Code != 200 {
		t.Fatalf("host seed: %d %s", w.Code, w.Body)
	}
	dns := &hostDomainDNS{target: "unproved.example"}
	registry, err := domains.New(db, f.p.Domain, bytes.Repeat([]byte{1}, 32), dns, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.p.domains = registry
	if _, err := registry.Add(ctx, &domainpb.Domain{Name: "work.example.com", Tunnel: "tools", Owner: f.tunnel.AccountID}); err != nil {
		t.Fatal(err)
	}
	namespace, err := registry.Add(ctx, &domainpb.Domain{Name: "*.apps.example.com", Tunnel: "tools", Owner: f.tunnel.AccountID})
	if err != nil {
		t.Fatal(err)
	}
	dns.target = namespace.CnameTarget
	if _, err := registry.Verify(ctx, namespace); err != nil {
		t.Fatal(err)
	}
	f.p.sshKeys, err = sshfront.NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public())
	if err != nil {
		t.Fatal(err)
	}
	publicKey := string(ssh.MarshalAuthorizedKey(key))
	registered, err := f.p.sshKeys.Add(ctx, "owner@example.com", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	client := discoverMCPClient(t, f)
	credentials := map[string]string{
		"owner-jwt": relayJWT(t, f.p, "owner@example.com"), "other-jwt": relayJWT(t, f.p, "other@example.com"),
		"alias-jwt": relayJWT(t, f.p, "alias@example.net"), "endpoint-token": "tunn_ep_route-fixture",
		"consumer-grant": "tunn_gr_route-fixture", "mcp-oauth": client.accessToken(t),
		"expired-jwt": prodAuthSigned(t, f.p, jwt.MapClaims{"type": "access", "email": "owner@example.com", "exp": time.Now().Add(-time.Hour).Unix()}, nil, nil),
	}
	// Consent proofs must use the exact cookie used to render that consent.
	credentials["owner-cookie"] = client.cookie.Value
	credentials["other-cookie"] = securityCookie(t, f.p, "other@example.com").Value
	credentials["login-proof"], err = f.p.generateMagicLinkToken("owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(credentials["endpoint-token"]))
	f.tunnel.updateAccessTokenDigest(digest[:])
	digest = sha256.Sum256([]byte(credentials["consumer-grant"]))
	grant, err := f.p.meter.CreateGrant(ctx, &meterpb.Grant{Owner: f.tunnel.AccountID, Endpoint: "tools", Consumer: "agent", TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	device, err := f.p.storage.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return &prodAuthFixture{f, client, credentials, grant.Id, registered.Fingerprint, publicKey, device.UserCode}
}

func (f *prodAuthFixture) routeRequest(t *testing.T, route prodAuthRoute, principal, authority string) *httptest.ResponseRecorder {
	t.Helper()
	path, body := route.path, route.body
	if strings.HasSuffix(path, "/grants/") {
		path += f.grantID
	}
	if route.pattern == "/api/mcp/clients" && route.method == "DELETE" {
		path += "&client_id=" + url.QueryEscape(f.client.clientID)
	}
	if route.pattern == "/api/ssh/keys" && route.method == "DELETE" {
		path += "?fingerprint=" + url.QueryEscape(f.fingerprint)
	}
	if path == "/oauth/authorize" && route.method == "GET" {
		path += "?" + f.client.query.Encode()
	}
	contentType := "application/json"
	switch body {
	case "key":
		data, err := json.Marshal(map[string]string{"public_key": f.publicKey})
		if err != nil {
			t.Fatal(err)
		}
		body = string(data)
	case "grant":
		digest := sha256.Sum256([]byte("tunn_gr_new-route-grant"))
		data, err := json.Marshal(&meterpb.Grant{Consumer: "new-agent", TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
		if err != nil {
			t.Fatal(err)
		}
		body = string(data)
	case "consent":
		body, contentType = f.client.consentForm(t).Encode(), "application/x-www-form-urlencoded"
	case "csrf":
		form := url.Values{"code": {f.userCode}, "client_id": {f.client.clientID}}
		if strings.HasSuffix(principal, "-cookie") {
			seed := httptest.NewRequest("GET", "https://tunn.test/", nil)
			seed.AddCookie(&http.Cookie{Name: authCookieName, Value: f.credentials[principal]})
			action := route.pattern
			if action == "/account/mcp" {
				action = "mcp-revoke"
			}
			csrf, err := f.p.createCSRFToken(seed, action)
			if err != nil {
				t.Fatal(err)
			}
			form.Set("csrf_token", csrf)
		}
		body, contentType = form.Encode(), "application/x-www-form-urlencoded"
	}
	if route.path == "/oauth/token" {
		contentType = "application/x-www-form-urlencoded"
	}
	r := httptest.NewRequest(route.method, "https://"+authority+path, strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("Origin", "https://tunn.test")
	if strings.HasSuffix(principal, "-cookie") {
		r.AddCookie(&http.Cookie{Name: authCookieName, Value: f.credentials[principal]})
	} else if credential := f.credentials[principal]; credential != "" {
		r.Header.Set("Authorization", "Bearer "+credential)
	}
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	return w
}

func TestProdAuthRoutePrincipalMatrix(t *testing.T) {
	for i, principal := range prodAuthPrincipals {
		t.Run(principal, func(t *testing.T) {
			f := newProdAuthFixture(t)
			for _, route := range prodAuthRoutes {
				t.Run(route.method+" "+route.path, func(t *testing.T) {
					w := f.routeRequest(t, route, principal, "tunn.test")
					if w.Code != route.want[i] {
						t.Fatalf("status = %d, want %d; body = %s", w.Code, route.want[i], w.Body)
					}
					// Later rows exercise a signed-in owner. Logout now revokes
					// this cookie, so perform a new account login for those rows.
					if principal == "owner-cookie" && route.path == "/auth/logout" && route.method == "POST" && w.Code == http.StatusFound {
						account, err := f.p.storage.GetAccountByEmail(context.Background(), "owner@example.com")
						if err != nil {
							t.Fatal(err)
						}
						login := httptest.NewRecorder()
						if err := f.p.setAccountCookie(login, account, "owner@example.com", "github"); err != nil {
							t.Fatal(err)
						}
						cookie := login.Result().Cookies()[0]
						f.credentials[principal] = cookie.Value
						f.client.cookie = cookie
					}
					if (principal == "other-jwt" || principal == "other-cookie") && route.method == "GET" && strings.HasPrefix(route.path, "/api/") && w.Code == 200 {
						for _, secret := range []string{f.grantID, f.client.clientID, f.fingerprint, "work.example.com", "workstation"} {
							if strings.Contains(w.Body.String(), secret) {
								t.Errorf("other account received owner's record %q", secret)
							}
						}
					}
				})
			}
		})
	}
}

// Require every registered platform route to appear in the policy table. This
// protects the inventory when another endpoint is added to createHandler.
func TestProdAuthRouteInventory(t *testing.T) {
	source, err := parser.ParseFile(token.NewFileSet(), "proxy.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	listed, registered := map[string]bool{}, map[string]bool{}
	for _, route := range prodAuthRoutes {
		listed[route.pattern] = true
	}
	ast.Inspect(source, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "HandleFunc" && selector.Sel.Name != "Handle" {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || receiver.Name != "mux" {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			t.Error("registered route must have a literal pattern for the policy inventory")
			return true
		}
		pattern, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Error(err)
			return true
		}
		registered[pattern] = true
		if !listed[pattern] {
			t.Errorf("registered route %q is missing from the principal matrix", pattern)
		}
		return true
	})
	for pattern := range listed {
		if !registered[pattern] {
			t.Errorf("matrix pattern %q is not registered", pattern)
		}
	}
}
