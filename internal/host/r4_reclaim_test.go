package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
)

// TXT is the only available proof, so this exercises the instructions the API
// delivers rather than the wildcard registry's alternative CNAME proof path.
type r4ReclaimDNS struct{ txt map[string][]string }

func (*r4ReclaimDNS) LookupCNAME(context.Context, string) (string, error) {
	return "", fmt.Errorf("no CNAME proof")
}
func (d *r4ReclaimDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	return d.txt[name], nil
}

func TestR4PublicAPIExposesCompetingProof(t *testing.T) {
	for _, name := range []string{"*.apps.example.com", "*.example.com"} {
		t.Run(name, func(t *testing.T) {
			p, _, _, _ := meteringRelay(t, false, "origin-content")
			db, err := store.InitForTest()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			const owner = "ad38bf44-0c4a-40ce-bdee-2d8579bf63cc"
			const other = "60b009cf-6023-4d39-8c69-39a692790e37"
			if _, err := db.Exec(`INSERT INTO accounts(id,primary_email,plan,created_at) VALUES(?, 'owner@example.com', 'pro', 1),(?, 'stranger@example.com', 'pro', 1),('attacker','attacker@example.com','pro',1)`, owner, other); err != nil {
				t.Fatal(err)
			}
			dns := &r4ReclaimDNS{txt: make(map[string][]string)}
			registry, err := domains.New(db, p.Domain, []byte("01234567890123456789012345678901"), dns, nil)
			if err != nil {
				t.Fatal(err)
			}
			p.domains = registry
			incumbent, err := registry.Add(context.Background(), &pb.Domain{Name: "*.example.com", Owner: "attacker"})
			if err != nil {
				t.Fatal(err)
			}
			handler := p.createHandler()
			ownerToken := relayJWT(t, p, "owner@example.com")
			otherToken := relayJWT(t, p, "stranger@example.com")
			body := fmt.Sprintf(`{"name":%q,"tunnel":"dashboard"}`, name)
			call := func(token string) *httptest.ResponseRecorder {
				request := httptest.NewRequest(http.MethodPost, "https://tunn.test/api/domains", strings.NewReader(body))
				if token != "" {
					request.Header.Set("Authorization", "Bearer "+token)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				return response
			}
			record := "_tunn-verification." + strings.TrimPrefix(name, "*.")
			proof := func(response *httptest.ResponseRecorder, account string) string {
				t.Helper()
				if response.Code != http.StatusConflict || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("expected uncached 409, got %d %s", response.Code, response.Body)
				}
				prefix := "unverified claim: prove ownership with TXT " + record + " = "
				target, ok := strings.CutPrefix(strings.TrimSpace(response.Body.String()), prefix)
				if !ok {
					t.Fatalf("public API discarded the competing TXT proof: %d %s", response.Code, response.Body)
				}
				target, ok = strings.CutSuffix(target, " and retry add within 24 hours")
				if !ok || !strings.HasPrefix(target, "dv-") || !strings.HasSuffix(target, ".tunn.test") || target == incumbent.CnameTarget {
					t.Fatalf("invalid or incumbent proof target: %s", response.Body)
				}
				var persisted string
				if err := db.QueryRow(`SELECT target FROM domain_reclaim_requests WHERE owner=? AND name=?`, account, name).Scan(&persisted); err != nil || target != persisted {
					t.Fatalf("proof is not scoped to the caller: target=%q persisted=%q err=%v", target, persisted, err)
				}
				return target
			}
			if response := call(""); response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "dv-") {
				t.Fatalf("unauthenticated proof access: %d %s", response.Code, response.Body)
			}
			response := call(ownerToken)
			target := proof(response, owner)
			otherResponse := call(otherToken)
			otherTarget := proof(otherResponse, other)
			if target == otherTarget || strings.Contains(response.Body.String(), otherTarget) || strings.Contains(otherResponse.Body.String(), target) {
				t.Fatal("competing accounts received another account's proof")
			}
			if repeated := proof(call(ownerToken), owner); repeated != target {
				t.Fatal("retry changed the pending proof")
			}
			// Publish exactly the TXT record and target delivered in the HTTP 409.
			// Another account cannot reclaim with the caller's published target.
			dns.txt[record] = []string{target}
			if repeated := proof(call(otherToken), other); repeated != otherTarget {
				t.Fatal("another account used the caller's published proof")
			}
			reclaimed := call(ownerToken)
			if reclaimed.Code != http.StatusCreated {
				t.Fatalf("proved reclaim failed: %d %s", reclaimed.Code, reclaimed.Body)
			}
			var binding pb.Domain
			if err := json.Unmarshal(reclaimed.Body.Bytes(), &binding); err != nil || binding.Name != name || binding.Owner != owner || binding.CnameTarget != target {
				t.Fatalf("unexpected reclaimed binding: %s err=%v", reclaimed.Body, err)
			}
			// The reclaimed owner is proven; even a different account's matching
			// TXT cannot replace it or obtain its proof target through this API.
			dns.txt[record] = []string{otherTarget}
			denied := call(otherToken)
			if denied.Code != http.StatusConflict || !strings.Contains(denied.Body.String(), "verified owner") || strings.Contains(denied.Body.String(), target) || strings.Contains(denied.Body.String(), otherTarget) {
				t.Fatalf("verified owner exclusion or target isolation failed: %d %s", denied.Code, denied.Body)
			}
			t.Logf("%s: authenticated 409 delivered caller TXT; published TXT retry returned 201; verified owner excluded competing account", name)
		})
	}
}
