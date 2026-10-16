package host

import (
	"context"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func prodAuthAwait(t *testing.T, results <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("authorization operation did not complete")
		return nil
	}
}

func TestProdAuthMCPOAuthConcurrentCodeExchange(t *testing.T) {
	f := newMCPOAuthFixture(t)
	f.p.mcpOAuth.db.SetMaxOpenConns(1)
	c := discoverMCPClient(t, f)
	body := c.tokenForm(c.code(t)).Encode()
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 4)
	for i := 0; i < 4; i++ {
		go func() {
			<-start
			results <- f.request("POST", c.token, body, "application/x-www-form-urlencoded", "", nil)
		}()
	}
	close(start)
	issued := 0
	for i := 0; i < 4; i++ {
		w := prodAuthAwait(t, results)
		if w.Code == 200 {
			issued++
		} else {
			prodAuthOAuthError(t, w, 400, "invalid_grant")
		}
	}
	grants, err := f.p.meter.ListGrants(context.Background(), &meterpb.ListGrantsRequest{Owner: f.tunnel.AccountID, Endpoint: "tools"})
	if err != nil || issued != 1 || len(grants.Grants) != 1 {
		t.Fatalf("one code issued %d responses and grants %v, error %v", issued, grants, err)
	}
}

func TestProdAuthMCPOAuthConcurrentConsent(t *testing.T) {
	f := newMCPOAuthFixture(t)
	f.p.mcpOAuth.db.SetMaxOpenConns(1)
	c := discoverMCPClient(t, f)
	body := c.consentForm(t).Encode()
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 4)
	for i := 0; i < 4; i++ {
		go func() {
			<-start
			results <- f.request("POST", c.authorize, body, "application/x-www-form-urlencoded", "", c.cookie)
		}()
	}
	close(start)
	issued := 0
	for i := 0; i < 4; i++ {
		w := prodAuthAwait(t, results)
		if w.Code == 302 {
			u, err := url.Parse(w.Header().Get("Location"))
			if err != nil || u.Query().Get("code") == "" {
				t.Fatalf("consent redirect: %s", w.Header())
			}
			issued++
		} else {
			prodAuthOAuthError(t, w, 503, "temporarily_unavailable")
		}
	}
	var codes int
	if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM mcp_oauth_codes`).Scan(&codes); err != nil || issued != 1 || codes != 1 {
		t.Fatalf("one consent issued %d responses and %d codes, error %v", issued, codes, err)
	}
}

type prodAuthIssuanceBarrier struct {
	metering.Backend
	metering.SharingBackend
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *prodAuthIssuanceBarrier) CreateGrant(ctx context.Context, grant *meterpb.Grant) (*meterpb.Grant, error) {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.release:
		return b.Backend.CreateGrant(ctx, grant)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestProdAuthMCPOAuthRevocationDuringIssuance(t *testing.T) {
	f := newMCPOAuthFixture(t)
	f.p.mcpOAuth.db.SetMaxOpenConns(1)
	c := discoverMCPClient(t, f)
	code := c.code(t)
	barrier := &prodAuthIssuanceBarrier{Backend: f.p.meter, SharingBackend: f.p.sharingBackend(), entered: make(chan struct{}), release: make(chan struct{})}
	f.p.meter = barrier
	var release sync.Once
	unblock := func() { release.Do(func() { close(barrier.release) }) }
	t.Cleanup(unblock)
	exchanges, revocations := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
	go func() {
		exchanges <- f.request("POST", c.token, c.tokenForm(code).Encode(), "application/x-www-form-urlencoded", "", nil)
	}()
	select {
	case <-barrier.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("code exchange did not reach grant issuance")
	}
	owner := relayJWT(t, f.p, "owner@example.com")
	started := make(chan struct{})
	go func() {
		close(started)
		revocations <- f.request("DELETE", "https://tunn.test/api/mcp/clients?tunnel=tools&client_id="+c.clientID, "", "", owner, nil)
	}()
	<-started
	unblock()
	if w := prodAuthAwait(t, exchanges); w.Code != 200 {
		t.Fatalf("in-progress exchange failed: %d %s", w.Code, w.Body)
	}
	if w := prodAuthAwait(t, revocations); w.Code != 204 {
		t.Fatalf("disconnect failed: %d %s", w.Code, w.Body)
	}
	grants, err := barrier.ListGrants(context.Background(), &meterpb.ListGrantsRequest{Owner: f.tunnel.AccountID, Endpoint: "tools"})
	if err != nil || len(grants.Grants) != 1 || !grants.Grants[0].Revoked {
		t.Fatalf("disconnect left an issued token active: %v, error %v", grants, err)
	}
	if w := f.request("POST", c.token, c.tokenForm(code).Encode(), "application/x-www-form-urlencoded", "", nil); w.Code != 400 {
		t.Fatal("completed exchange could be reused after revocation")
	}
}

func TestProdAuthMCPOAuthConcurrentRegistrationAllowance(t *testing.T) {
	f := newMCPOAuthFixture(t)
	f.p.mcpOAuth.db.SetMaxOpenConns(1)
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 6)
	for i := 0; i < 6; i++ {
		go func() {
			<-start
			results <- f.request("POST", "https://tunn.test/oauth/register", `{"redirect_uris":["https://connector.example/cb"]}`, "application/json", "", nil)
		}()
	}
	close(start)
	registered, denied := 0, 0
	for i := 0; i < 6; i++ {
		w := prodAuthAwait(t, results)
		switch w.Code {
		case 201:
			registered++
		case 429:
			prodAuthOAuthError(t, w, 429, "temporarily_unavailable")
			if w.Header().Get("Retry-After") != "300" {
				t.Fatal("registration denial lost its retry time")
			}
			denied++
		default:
			t.Fatalf("registration returned %d: %s", w.Code, w.Body)
		}
	}
	if registered != 5 || denied != 1 {
		t.Fatalf("concurrent registration allowance = %d accepted, %d denied", registered, denied)
	}
}
