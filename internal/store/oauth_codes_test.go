package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func oauthCodeFixture(t *testing.T, accountID string) OAuthCodeCreate {
	t.Helper()
	code, err := grantRandom(32)
	if err != nil {
		t.Fatal(err)
	}
	consent, err := grantRandom(32)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := grantRandom(32)
	if err != nil {
		t.Fatal(err)
	}
	return OAuthCodeCreate{Code: code, ConsentID: consent, AccountID: accountID, EndpointID: "build", ClientID: "synthetic-hosted-client", RedirectURI: "https://client.test/callback", Resource: "https://build.tunn.test/mcp", Scope: "mcp", CodeChallenge: challenge, ExpiresAt: time.Now().Add(2 * time.Minute), GrantExpiresAt: time.Now().Add(time.Hour), RequestLimit: 5, Label: "hosted investigator"}
}

func oauthExchangeFixture(q OAuthCodeCreate) OAuthCodeExchange {
	return OAuthCodeExchange{Code: q.Code, ClientID: q.ClientID, RedirectURI: q.RedirectURI, Resource: q.Resource, CodeChallenge: q.CodeChallenge}
}

func oauthGrantCount(t *testing.T, db *sql.DB, want int) {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM endpoint_grants`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Fatalf("minted grants=%d want%d", n, want)
	}
}

func TestOAuthCodeBindingsConsentReplayAndGrantLifecycle(t *testing.T) {
	db, grants, acc := grantFixture(t)
	s := NewOAuthCodeStore(db)
	ctx := context.Background()
	q := oauthCodeFixture(t, acc.ID)
	if err := s.Create(ctx, q); err != nil {
		t.Fatal(err)
	}
	oauthGrantCount(t, db, 0)
	var digest, consentDigest, client, resource, scope string
	if err := db.QueryRow(`SELECT code_digest,consent_digest,client_id,resource,scope FROM oauth_codes`).Scan(&digest, &consentDigest, &client, &resource, &scope); err != nil {
		t.Fatal(err)
	}
	if digest != grantDigest(q.Code) || consentDigest != grantDigest(q.ConsentID) || digest == q.Code || consentDigest == q.ConsentID || client != q.ClientID || resource != q.Resource || scope != q.Scope {
		t.Fatal("code/consent digest or bindings persisted incorrectly")
	}
	duplicate := oauthCodeFixture(t, acc.ID)
	duplicate.ConsentID = q.ConsentID
	if err := s.Create(ctx, duplicate); !errors.Is(err, ErrOAuthInvalidGrant) {
		t.Fatalf("consent replay accepted=%v", err)
	}
	duplicate = q
	duplicate.ClientID = "another-client"
	if err := s.Create(ctx, duplicate); !errors.Is(err, ErrOAuthInvalidGrant) {
		t.Fatalf("code bindings overwritten=%v", err)
	}
	for _, mutate := range []func(*OAuthCodeExchange){
		func(q *OAuthCodeExchange) { q.ClientID = "other-client" },
		func(q *OAuthCodeExchange) { q.RedirectURI = "https://client.test/callback?extra=1" },
		func(q *OAuthCodeExchange) { q.Resource = "https://other.tunn.test/mcp" },
		func(q *OAuthCodeExchange) { q.CodeChallenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
		func(q *OAuthCodeExchange) { q.Code = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
	} {
		bad := oauthExchangeFixture(q)
		mutate(&bad)
		if g, token, err := s.Exchange(ctx, bad); !errors.Is(err, ErrOAuthInvalidGrant) || g != nil || token != "" {
			t.Fatalf("invalid binding minted grant: %+v tokenExists=%v err=%v", g, token != "", err)
		}
		oauthGrantCount(t, db, 0)
	}
	g, token, err := s.Exchange(ctx, oauthExchangeFixture(q))
	if err != nil || g == nil || token == "" || g.AccountID != acc.ID || g.EndpointID != q.EndpointID || g.Label != q.Label || g.RequestLimit != q.RequestLimit {
		t.Fatalf("exchange=%+v %v", g, err)
	}
	oauthGrantCount(t, db, 1)
	var consumed int64
	var grantID, tokenDigest string
	if err := db.QueryRow(`SELECT consumed_at,grant_id FROM oauth_codes WHERE code_digest=?`, grantDigest(q.Code)).Scan(&consumed, &grantID); err != nil {
		t.Fatal(err)
	}
	if consumed == 0 || grantID != g.ID {
		t.Fatal("code not consumed atomically")
	}
	if err := db.QueryRow(`SELECT token_digest FROM endpoint_grants WHERE id=?`, g.ID).Scan(&tokenDigest); err != nil {
		t.Fatal(err)
	}
	if tokenDigest != grantDigest(token) || tokenDigest == token {
		t.Fatal("raw OAuth access token persisted")
	}
	if g, token, err := s.Exchange(ctx, oauthExchangeFixture(q)); !errors.Is(err, ErrOAuthInvalidGrant) || g != nil || token != "" {
		t.Fatal("one-use code minted again")
	}
	checkAdmission(t, grants, GrantAdmissionRequest{AccountID: acc.ID, EndpointID: q.EndpointID, Token: token, RequestID: "oauth-call"}, "grant", 200)
	if found, err := grants.Revoke(ctx, acc.ID, g.ID); err != nil || !found {
		t.Fatal("OAuth grant cannot be owner-revoked")
	}
	checkAdmission(t, grants, GrantAdmissionRequest{AccountID: acc.ID, EndpointID: q.EndpointID, Token: token, RequestID: "oauth-call-two"}, "grant_revoked", 403)
}

func TestOAuthCodeRollbackExpiryCancellationAndValidation(t *testing.T) {
	db, _, acc := grantFixture(t)
	s := NewOAuthCodeStore(db)
	ctx := context.Background()
	q := oauthCodeFixture(t, acc.ID)
	if err := s.Create(ctx, q); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range []string{
		`CREATE TRIGGER fail_oauth BEFORE INSERT ON endpoint_grants BEGIN SELECT RAISE(ABORT,'synthetic'); END`,
		`CREATE TRIGGER fail_oauth BEFORE UPDATE OF grant_id ON oauth_codes BEGIN SELECT RAISE(ABORT,'synthetic'); END`,
	} {
		if _, err := db.Exec(trigger); err != nil {
			t.Fatal(err)
		}
		if g, token, err := s.Exchange(ctx, oauthExchangeFixture(q)); err == nil || g != nil || token != "" {
			t.Fatal("storage failure returned a credential")
		}
		oauthGrantCount(t, db, 0)
		var consumed int64
		if err := db.QueryRow(`SELECT consumed_at FROM oauth_codes WHERE code_digest=?`, grantDigest(q.Code)).Scan(&consumed); err != nil || consumed != 0 {
			t.Fatalf("partial code consumption=%d %v", consumed, err)
		}
		if _, err := db.Exec(`DROP TRIGGER fail_oauth`); err != nil {
			t.Fatal(err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if g, token, err := s.Exchange(canceled, oauthExchangeFixture(q)); err == nil || g != nil || token != "" {
		t.Fatal("canceled request minted")
	}
	oauthGrantCount(t, db, 0)
	if _, err := db.Exec(`UPDATE oauth_codes SET expires_at=? WHERE code_digest=?`, time.Now().Add(-time.Second).UnixMilli(), grantDigest(q.Code)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Exchange(ctx, oauthExchangeFixture(q)); !errors.Is(err, ErrOAuthInvalidGrant) {
		t.Fatalf("expired code=%v", err)
	}
	oauthGrantCount(t, db, 0)
	for _, mutate := range []func(*OAuthCodeCreate){
		func(q *OAuthCodeCreate) { q.Code = "bad" }, func(q *OAuthCodeCreate) { q.ConsentID = "short" }, func(q *OAuthCodeCreate) { q.CodeChallenge = "bad" },
		func(q *OAuthCodeCreate) { q.ClientID = "" }, func(q *OAuthCodeCreate) { q.RedirectURI = "https://client.test/callback#fragment" }, func(q *OAuthCodeCreate) { q.Resource = "relative" },
		func(q *OAuthCodeCreate) { q.ExpiresAt = time.Now().Add(MaxOAuthCodeLifetime + time.Minute) }, func(q *OAuthCodeCreate) { q.ExpiresAt = time.Now().Add(-time.Second) },
		func(q *OAuthCodeCreate) { q.Scope = "" }, func(q *OAuthCodeCreate) { q.GrantExpiresAt = time.Now().Add(MaxGrantLifetime + time.Hour) }, func(q *OAuthCodeCreate) { q.RequestLimit = 0 },
	} {
		bad := oauthCodeFixture(t, acc.ID)
		mutate(&bad)
		if err := s.Create(ctx, bad); !errors.Is(err, ErrOAuthInvalidRequest) {
			t.Fatalf("invalid code metadata accepted=%v", err)
		}
	}
	if _, _, err := s.Exchange(ctx, OAuthCodeExchange{Code: "malformed"}); !errors.Is(err, ErrOAuthInvalidRequest) {
		t.Fatal("malformed exchange accepted")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if g, token, err := s.Exchange(ctx, oauthExchangeFixture(q)); err == nil || g != nil || token != "" {
		t.Fatal("closed database minted")
	}
}

func TestOAuthCodeConcurrentExchangePersistenceAndMergedOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	accounts := NewAccountStore(db)
	old, err := accounts.FindOrCreateByEmails([]string{"oauth-old@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	q := oauthCodeFixture(t, old.ID)
	s := NewOAuthCodeStore(db)
	if err := s.Create(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	next, err := accounts.FindOrCreateByEmails([]string{"oauth-new@test.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpdatePlan(next.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{old.PrimaryEmail, next.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(8)
	var wg sync.WaitGroup
	results := make(chan *Grant, 32)
	failures := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, _, err := NewOAuthCodeStore(db).Exchange(context.Background(), oauthExchangeFixture(q))
			if err != nil {
				failures <- err
				return
			}
			results <- g
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	issued, rejected := 0, 0
	for g := range results {
		issued++
		if g.AccountID != merged.ID {
			t.Fatalf("stale owner grant=%+v", g)
		}
	}
	for err := range failures {
		if !errors.Is(err, ErrOAuthInvalidGrant) {
			t.Fatal(err)
		}
		rejected++
	}
	if issued != 1 || rejected != 31 {
		t.Fatalf("exchanges issued=%d rejected=%d", issued, rejected)
	}
	oauthGrantCount(t, db, 1)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if g, token, err := NewOAuthCodeStore(db).Exchange(context.Background(), oauthExchangeFixture(q)); !errors.Is(err, ErrOAuthInvalidGrant) || g != nil || token != "" {
		t.Fatal("restart permitted second mint after lost response")
	}
	out, err := NewGrantStore(db).List(context.Background(), old.ID, q.EndpointID)
	if err != nil || len(out) != 1 || out[0].AccountID != merged.ID || out[0].Label != q.Label {
		t.Fatalf("owner cannot recover/revoke grant metadata: %+v %v", out, err)
	}
}
