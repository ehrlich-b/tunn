package host

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"github.com/golang-jwt/jwt/v4"
)

func TestNamespacePublisherActualDurableTokenAndRevocation(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			p := durableFixture(t)
			p.config.NodeSecret = "fixture-cluster"
			token := durableLogin(t, p)
			account, err := p.storage.GetAccountByEmail(context.Background(), "owner@example.com")
			if err != nil {
				t.Fatal(err)
			}
			accounts := store.NewAccountStore(p.devices.db)
			if err := accounts.UpdatePlan(account.ID, "pro"); err != nil {
				t.Fatal(err)
			}
			if legacy {
				if err := accounts.ReserveSubdomain(account.ID, "grafana"); err != nil {
					t.Fatal(err)
				}
			}
			dns := new(hostDomainDNS)
			registry, err := domains.New(p.devices.db, p.Domain, []byte("01234567890123456789012345678901"), dns, nil)
			if err != nil {
				t.Fatal(err)
			}
			p.domains = registry
			d, err := registry.Add(context.Background(), &domainpb.Domain{Name: "*.apps.customer.test", Tunnel: "grafana", Owner: account.ID})
			if err != nil {
				t.Fatal(err)
			}
			dns.target = d.CnameTarget
			if _, err := registry.Verify(context.Background(), d); err != nil {
				t.Fatal(err)
			}
			handler := p.createHandler()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.Host = p.Domain; handler.ServeHTTP(w, r) }))
			defer server.Close()
			c := &client.ManagementClient{ServerURL: server.URL, OwnerToken: token.Access, HTTPClient: server.Client()}
			if id, err := c.NamespaceTunnel(context.Background(), "apps.customer.test", "grafana"); err != nil || id != d.AppNames[0].Tunnel {
				t.Fatalf("actual durable publisher lookup: id=%s err=%v", id, err)
			}
			// Exercise the live registry lookup through a terminating edge too.
			authority := httptest.NewTLSServer(handler)
			defer authority.Close()
			edge := securityProxy(p.storage)
			edge.config.NodeSecret = p.config.NodeSecret
			edge.config.JWTSecret = p.config.JWTSecret
			edge.domains = registry
			edge.config.Insecure = true // local fixture CA only
			edge.loginNodeHTTPAddr = strings.TrimPrefix(authority.URL, "https://")
			edgeLookup := func() *httptest.ResponseRecorder {
				req := httptest.NewRequest("POST", "https://"+p.Domain+"/api/domains/publisher", strings.NewReader(`{"name":"grafana.apps.customer.test"}`))
				req.Header.Set("Authorization", "Bearer "+token.Access)
				rec := httptest.NewRecorder()
				edge.handleNamespacePublisher(rec, req)
				return rec
			}
			if rec := edgeLookup(); rec.Code != 200 {
				t.Fatalf("forwarded durable lookup: %d %s", rec.Code, rec.Body)
			}
			// Durable publisher tokens still have no owner-management authority.
			for _, method := range []string{"GET", "POST", "DELETE"} {
				path := "/api/domains"
				if method == "DELETE" {
					path += "/*.apps.customer.test"
				}
				req := httptest.NewRequest(method, "https://"+p.Domain+path, strings.NewReader(`{"name":"*.apps.attacker.test","tunnel":"grafana"}`))
				req.Header.Set("Authorization", "Bearer "+token.Access)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != 401 {
					t.Fatalf("device token broadened management authority: %s %d", method, rec.Code)
				}
			}
			if _, err := c.NamespaceTunnel(context.Background(), "apps.customer.test", "missing"); err == nil {
				t.Fatal("unregistered app lookup succeeded")
			}
			// The server resolves current ownership, not an email in arbitrary JWT text.
			other, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"other@example.com"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.devices.db.Exec(`UPDATE custom_domains SET owner=? WHERE name=?`, other.ID, d.Name); err != nil {
				t.Fatal(err)
			}
			if err := accounts.UpdatePlan(other.ID, "pro"); err != nil {
				t.Fatal(err)
			}
			if _, err := c.NamespaceTunnel(context.Background(), "apps.customer.test", "grafana"); err == nil {
				t.Fatal("foreign namespace lookup succeeded")
			}
			if _, err := p.devices.db.Exec(`UPDATE custom_domains SET owner=? WHERE name=?`, account.ID, d.Name); err != nil {
				t.Fatal(err)
			}
			// Signature-valid but scope/expiry-invalid credentials fail closed.
			for _, claims := range []jwt.MapClaims{
				{"email": "owner@example.com", "type": "device_access", "iss": "tunn", "aud": "wrong", "scope": "publish connect", "device": token.Device, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()},
				{"email": "owner@example.com", "type": "device_access", "iss": "tunn", "aud": "tunn-tunnels", "scope": "publish connect", "device": token.Device, "iat": time.Now().Add(-10 * time.Minute).Unix(), "exp": time.Now().Add(-time.Minute).Unix()},
			} {
				bad, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
				c.OwnerToken = bad
				if _, err := c.NamespaceTunnel(context.Background(), "apps.customer.test", "grafana"); err == nil {
					t.Fatal("invalid device authority accepted")
				}
			}
			c.OwnerToken = token.Access
			if _, err := p.devices.db.Exec(`UPDATE durable_devices SET revoked=1 WHERE id=?`, token.Device); err != nil {
				t.Fatal(err)
			}
			if _, err := c.NamespaceTunnel(context.Background(), "apps.customer.test", "grafana"); err == nil {
				t.Fatal("revoked device still resolved publisher")
			}
			if rec := edgeLookup(); rec.Code != 401 {
				t.Fatalf("forwarded revoked-device lookup: %d", rec.Code)
			}
		})
	}
}

func TestNamespacePublisherDeviceForwardingFailsClosed(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	_, registry, _ := domainProxyFixture(t)
	p.domains = registry
	p.devices = nil
	req := httptest.NewRequest("POST", "https://"+p.Domain+"/api/domains/publisher", strings.NewReader(`{"name":"grafana.apps.customer.test"}`))
	req.Header.Set("Authorization", "Bearer "+token.Access)
	rec := httptest.NewRecorder()
	p.handleNamespacePublisher(rec, req)
	if rec.Code != 503 {
		t.Fatalf("missing live device authority: %d", rec.Code)
	}
}

func TestNamespacePublisherAndLeaseAfterAccountMerge(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprint("RPC=", remote), func(t *testing.T) {
			p := durableFixture(t)
			original := durableLogin(t, p)
			local := p.storage.(*storage.LocalStorage)
			accounts := store.NewAccountStore(p.devices.db)
			// Create the second identity before invoking the existing provider merge path.
			survivor, err := accounts.FindOrCreateByEmails([]string{"aaa-survivor@example.com"}, "github")
			if err != nil {
				t.Fatal(err)
			}
			owner, err := local.GetAccountByEmail(context.Background(), "owner@example.com")
			if err != nil {
				t.Fatal(err)
			}
			if err := accounts.UpdatePlan(owner.ID, "pro"); err != nil {
				t.Fatal(err)
			}
			dns := new(hostDomainDNS)
			registry, err := domains.New(p.devices.db, p.Domain, []byte("01234567890123456789012345678901"), dns, nil)
			if err != nil {
				t.Fatal(err)
			}
			p.domains = registry
			domain, err := registry.Add(context.Background(), &domainpb.Domain{Name: "*.merge.customer.test", Tunnel: "grafana", Owner: owner.ID})
			if err != nil {
				t.Fatal(err)
			}
			dns.target = domain.CnameTarget
			if _, err := registry.Verify(context.Background(), domain); err != nil {
				t.Fatal(err)
			}
			// Force the other account to survive while preserving namespace entitlement.
			if err := accounts.UpdatePlan(survivor.ID, "pro"); err != nil {
				t.Fatal(err)
			}
			if err := accounts.UpdatePlan(owner.ID, "free"); err != nil {
				t.Fatal(err)
			}
			merged, err := accounts.FindOrCreateByEmails([]string{owner.PrimaryEmail, survivor.PrimaryEmail}, "github")
			if err != nil || merged.ID != survivor.ID {
				t.Fatal("merge did not choose survivor", merged, err)
			}
			if remote {
				p.storage = securityReplicaStorage(t, local)
			}
			response, refreshed := durableRefresh(p, original.Refresh, strings.Repeat("m", 43))
			if response.Code != 200 {
				t.Fatal(response.Code, response.Body)
			}
			var storedID string
			if err := p.devices.db.QueryRow("SELECT account_id FROM durable_devices WHERE id=?", original.Device).Scan(&storedID); err != nil || storedID != owner.ID {
				t.Fatal(storedID, err)
			}
			if signedAccountID(refreshed.Access) != merged.ID {
				t.Fatal("refresh did not resolve merge")
			}
			request := httptest.NewRequest("POST", "https://"+p.Domain+"/api/domains/publisher", strings.NewReader(`{"name":"grafana.merge.customer.test"}`))
			request.Header.Set("Authorization", "Bearer "+refreshed.Access)
			result := httptest.NewRecorder()
			p.handleNamespacePublisher(result, request)
			if result.Code != 200 {
				t.Fatal("namespace after merge", result.Code, result.Body)
			}
			_, device, expiry, err := parseDeviceToken(original.Access, p.getJWTSigningKey(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			lease := &publisherDeviceLease{authority: p.storage, accountID: signedAccountID(original.Access), device: device, expiry: expiry}
			if err := lease.renew(context.Background(), refreshed.Access, p.getJWTSigningKey(), time.Now()); err != nil {
				t.Fatal("renewal after merge", err)
			}
			// Canonical UUID comparison also accepts equivalent encodings.
			lease.accountID = strings.ToUpper(owner.ID)
			if err := lease.renew(context.Background(), refreshed.Access, p.getJWTSigningKey(), time.Now()); err != nil {
				t.Fatal("obsolete UUID case renewal", err)
			}
			foreign := durableLogin(t, p)
			// A different device in the same merged account cannot renew this lease.
			if err := lease.renew(context.Background(), foreign.Access, p.getJWTSigningKey(), time.Now()); err == nil {
				t.Fatal("different device renewed lease")
			}
		})
	}
}
