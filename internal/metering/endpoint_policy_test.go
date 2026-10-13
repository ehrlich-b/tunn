package metering

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/trafficpolicy"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func policyResource(t *testing.T, s *Store, owner, endpoint string) string {
	t.Helper()
	out, err := s.Sharing(context.Background(), &pb.SharingRequest{Operation: "register", Owner: owner, Endpoint: endpoint, Mode: "public"})
	if err != nil {
		t.Fatal(err)
	}
	return out.Resources[0].Id
}
func setPolicy(t *testing.T, s *Store, owner, endpoint string, p *trafficpolicy.Policy) {
	t.Helper()
	data, _ := json.Marshal(p)
	if _, err := s.EndpointPolicy(context.Background(), &pb.EndpointPolicyRequest{Operation: "set", Owner: owner, Endpoint: endpoint, PolicyJson: data}); err != nil {
		t.Fatal(err)
	}
}
func policyAdmit(t *testing.T, s *Store, owner, endpoint, resource, ip string) *pb.Decision {
	t.Helper()
	out, err := s.EndpointPolicy(context.Background(), &pb.EndpointPolicyRequest{Operation: "admit", Owner: owner, Endpoint: endpoint, ResourceId: resource, ClientIp: ip})
	if err != nil {
		t.Fatal(err)
	}
	return out.Decision
}

func TestPolicyConcurrentBurstAndDurableRefill(t *testing.T) {
	s, db := fixture(t)
	resource := policyResource(t, s, "owner", "api")
	p := &trafficpolicy.Policy{RateLimits: trafficpolicy.RateLimits{PerIP: &trafficpolicy.Limit{RequestsPerMinute: 60, Burst: 3}, PerAccount: &trafficpolicy.Limit{RequestsPerMinute: 30, Burst: 3}}}
	setPolicy(t, s, "owner", "api", p)
	var wg sync.WaitGroup
	var allowed atomic.Int64
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if policyAdmit(t, s, "owner", "api", resource, "192.0.2.1").Allowed {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 3 {
		t.Fatalf("allowed=%d want 3", allowed.Load())
	}
	d := policyAdmit(t, s, "owner", "api", resource, "192.0.2.2")
	if d.Allowed || d.Status != 429 || d.RetryAfter != 2 || d.Reason != "policy_account_rate" {
		t.Fatalf("decision=%v", d)
	}
	restarted, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return testNow }
	if policyAdmit(t, restarted, "owner", "api", resource, "192.0.2.1").Allowed {
		t.Fatal("restart erased burst debt")
	}
	restarted.now = func() time.Time { return testNow.Add(time.Second) }
	if d := policyAdmit(t, restarted, "owner", "api", resource, "192.0.2.1"); d.Allowed || d.RetryAfter != 1 {
		t.Fatalf("rounded refill=%v", d)
	}
	restarted.now = func() time.Time { return testNow.Add(2 * time.Second) }
	if !policyAdmit(t, restarted, "owner", "api", resource, "192.0.2.1").Allowed {
		t.Fatal("refill denied")
	}
}

func TestPolicyIPCanonicalizationAtomicDenialAndEndpointIsolation(t *testing.T) {
	s, _ := fixture(t)
	resource := policyResource(t, s, "owner", "api")
	other := policyResource(t, s, "owner", "other")
	p := &trafficpolicy.Policy{RateLimits: trafficpolicy.RateLimits{PerIP: &trafficpolicy.Limit{RequestsPerMinute: 1, Burst: 1}, PerAccount: &trafficpolicy.Limit{RequestsPerMinute: 1, Burst: 2}}}
	setPolicy(t, s, "owner", "api", p)
	setPolicy(t, s, "owner", "other", p)
	if !policyAdmit(t, s, "owner", "api", resource, "192.0.2.1").Allowed {
		t.Fatal("first denied")
	}
	if d := policyAdmit(t, s, "owner", "api", resource, "::ffff:192.0.2.1"); d.Allowed || d.Reason != "policy_ip_rate" {
		t.Fatalf("mapped IP bypass: %v", d)
	}
	if !policyAdmit(t, s, "owner", "api", resource, "192.0.2.2").Allowed {
		t.Fatal("denial consumed aggregate token")
	}
	if !policyAdmit(t, s, "owner", "other", other, "192.0.2.1").Allowed {
		t.Fatal("endpoints shared limits")
	}
}

func TestPolicyOwnerGenerationAndConfiguration(t *testing.T) {
	s, _ := fixture(t)
	id := policyResource(t, s, "first", "api")
	p := &trafficpolicy.Policy{Headers: trafficpolicy.Headers{Add: []trafficpolicy.Header{{Name: "X-Test", Value: "owner-configured"}}}, RateLimits: trafficpolicy.RateLimits{PerIP: &trafficpolicy.Limit{RequestsPerMinute: 1, Burst: 1}}}
	setPolicy(t, s, "first", "api", p)
	policyAdmit(t, s, "first", "api", id, "192.0.2.1")
	setPolicy(t, s, "first", "api", p)
	if policyAdmit(t, s, "first", "api", id, "192.0.2.1").Allowed {
		t.Fatal("PUT reset rate debt")
	}
	if _, err := s.EndpointPolicy(context.Background(), &pb.EndpointPolicyRequest{Operation: "get", Owner: "second", Endpoint: "api"}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-owner read: %v", err)
	}
	if _, err := s.EndpointPolicy(context.Background(), &pb.EndpointPolicyRequest{Operation: "admit", Owner: "first", Endpoint: "api"}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing generation: %v", err)
	}
	newID := policyResource(t, s, "second", "api")
	if newID == id {
		t.Fatal("resource generation reused")
	}
	out, err := s.EndpointPolicy(context.Background(), &pb.EndpointPolicyRequest{Operation: "get", Owner: "second", Endpoint: "api"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := trafficpolicy.Decode(out.PolicyJson)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Headers.Add) != 0 || policy.RateLimits.PerIP != nil {
		t.Fatal("new owner inherited policy")
	}
	if _, err := s.EndpointPolicy(context.Background(), &pb.EndpointPolicyRequest{Operation: "admit", Owner: "first", Endpoint: "api", ResourceId: id}); status.Code(err) != codes.NotFound {
		t.Fatalf("stale owner admitted: %v", err)
	}
	var n int
	if err = s.db.QueryRow(`SELECT count(*) FROM endpoint_policy_buckets WHERE resource=?`, id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("old debt retained: %d %v", n, err)
	}
}

func TestPolicyCapacityNeverEvictsDebt(t *testing.T) {
	s, _ := fixture(t)
	s.maxPolicyBuckets = 2
	s.maxEndpointPolicyBuckets = 2
	id := policyResource(t, s, "owner", "api")
	setPolicy(t, s, "owner", "api", &trafficpolicy.Policy{RateLimits: trafficpolicy.RateLimits{PerIP: &trafficpolicy.Limit{RequestsPerMinute: 60, Burst: 1}}})
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if !policyAdmit(t, s, "owner", "api", id, ip).Allowed {
			t.Fatal("initial capacity denied")
		}
	}
	if d := policyAdmit(t, s, "owner", "api", id, "192.0.2.3"); d.Allowed || d.Reason != "policy_capacity" {
		t.Fatalf("capacity=%v", d)
	}
	if policyAdmit(t, s, "owner", "api", id, "192.0.2.1").Allowed {
		t.Fatal("capacity evicted debt")
	}
	s.now = func() time.Time { return testNow.Add(time.Second) }
	if !policyAdmit(t, s, "owner", "api", id, "192.0.2.3").Allowed {
		t.Fatal("full buckets did not expire")
	}
}

func TestPolicyChangedRateStartsAtUpdateAndClear(t *testing.T) {
	s, _ := fixture(t)
	id := policyResource(t, s, "owner", "api")
	p := &trafficpolicy.Policy{RateLimits: trafficpolicy.RateLimits{PerIP: &trafficpolicy.Limit{RequestsPerMinute: 60, Burst: 2}}}
	setPolicy(t, s, "owner", "api", p)
	policyAdmit(t, s, "owner", "api", id, "192.0.2.1")
	policyAdmit(t, s, "owner", "api", id, "192.0.2.1")
	s.now = func() time.Time { return testNow.Add(500 * time.Millisecond) }
	p.RateLimits.PerIP.RequestsPerMinute = 1
	setPolicy(t, s, "owner", "api", p)
	s.now = func() time.Time { return testNow.Add(time.Second) }
	if d := policyAdmit(t, s, "owner", "api", id, "192.0.2.1"); d.Allowed || d.RetryAfter != 30 {
		t.Fatalf("old rate continued after PUT: %v", d)
	}
	if _, err := s.EndpointPolicy(context.Background(), &pb.EndpointPolicyRequest{Operation: "clear", Owner: "owner", Endpoint: "api"}); err != nil {
		t.Fatal(err)
	}
	if !policyAdmit(t, s, "owner", "api", id, "192.0.2.1").Allowed {
		t.Fatal("clear did not remove limit")
	}
}

func TestPolicyGrantRevalidationIsAtomicWithTokens(t *testing.T) {
	s, db := fixture(t)
	id := policyResource(t, s, "owner@example.com", "api")
	setPolicy(t, s, "owner@example.com", "api", &trafficpolicy.Policy{RateLimits: trafficpolicy.RateLimits{PerIP: &trafficpolicy.Limit{RequestsPerMinute: 1, Burst: 1}, PerAccount: &trafficpolicy.Limit{RequestsPerMinute: 1, Burst: 1}}})
	g := newGrant(t, s, 0, 0, 0)
	if _, err := s.RevokeGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	out, err := s.EndpointPolicy(context.Background(), &pb.EndpointPolicyRequest{Operation: "admit", Owner: g.Owner, Endpoint: "api", ResourceId: id, ClientIp: "192.0.2.1", GrantId: g.Id})
	if err != nil || out.Decision.Allowed || out.Decision.Status != 403 || out.Decision.Reason != "grant_revoked" {
		t.Fatalf("atomic revocation=%v %v", out, err)
	}
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM endpoint_policy_buckets`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("revoked admission reserved tokens: %d %v", n, err)
	}
	if !policyAdmit(t, s, g.Owner, "api", id, "192.0.2.1").Allowed {
		t.Fatal("revoked grant drained legitimate tokens")
	}
}
