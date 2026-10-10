package domains

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
)

type edgeACMEFailure struct {
	fake *fakeDirectory
	kind string
}

func (f edgeACMEFailure) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := f.fake.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if request.URL.Path == "/challenge/1" && f.kind == "acceptance failure" {
		response.StatusCode = 400
		response.Body = io.NopCloser(bytes.NewBufferString(`{"type":"urn:ietf:params:acme:error:unauthorized","detail":"fixture rejection"}`))
		return response, nil
	}
	if request.URL.Path != "/auth/1" {
		return response, nil
	}
	var auth map[string]any
	if err := json.NewDecoder(response.Body).Decode(&auth); err != nil {
		return nil, err
	}
	_ = response.Body.Close()
	switch f.kind {
	case "wrong identifier":
		auth["identifier"] = map[string]string{"type": "dns", "value": "other.example.com"}
	case "wildcard identifier":
		auth["wildcard"] = true
	case "no HTTP01":
		auth["challenges"] = []map[string]string{{"type": "dns-01", "token": "fixture-token"}}
	case "authorization failure":
		if f.fake.authorized {
			auth["status"] = "invalid"
			auth["error"] = map[string]string{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "fixture authorization failure"}
		}
	}
	data, err := json.Marshal(auth)
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	response.ContentLength = int64(len(data))
	return response, nil
}

func TestEdgeACMEFailureDoesNotLeaveChallengesOrRoutes(t *testing.T) {
	for _, kind := range []string{"wrong identifier", "wildcard identifier", "no HTTP01", "acceptance failure", "authorization failure"} {
		t.Run(kind, func(t *testing.T) {
			r, dns, db := domainFixture(t, nil)
			d := addDomain(t, r, "work.example.com", "site", "one")
			dns.records[d.Name] = d.CnameTarget
			fake := &fakeDirectory{t: t, authority: r}
			httpClient := &http.Client{Transport: edgeACMEFailure{fake: fake, kind: kind}}
			if err := r.ConfigureACME("https://acme.invalid/directory", "fixture@example.com", httpClient); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Verify(context.Background(), d); err == nil {
				t.Fatal("invalid ACME order accepted")
			}
			if _, err := r.Route(context.Background(), d); err == nil || fake.issued != 0 {
				t.Fatalf("failed order activated a route or finalized: %v issued=%d", err, fake.issued)
			}
			if _, err := r.Challenge(context.Background(), &pb.ChallengeRequest{Name: d.Name, Token: "fake-http01-token"}); err == nil {
				t.Fatal("failed order left challenge reachable")
			}
			var count int
			if err := db.QueryRow("SELECT count(*) FROM domain_challenges").Scan(&count); err != nil || count != 0 {
				t.Fatalf("failed order left persisted challenge: %d %v", count, err)
			}
		})
	}
}
