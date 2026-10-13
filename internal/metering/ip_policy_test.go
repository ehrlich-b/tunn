package metering

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/ippolicy"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func policyCall(t *testing.T, s *Store, operation, owner, endpoint string, allow, deny []string) *pb.IPPolicy {
	t.Helper()
	out, err := s.IPPolicy(context.Background(), &pb.IPPolicyRequest{Operation: operation, Owner: owner, Endpoint: endpoint, AllowCidrs: allow, DenyCidrs: deny})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIPPolicyAuthorityContentionHonorsDeadline(t *testing.T) {
	s, _ := fixture(t)
	s.mu <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := s.IPPolicy(ctx, &pb.IPPolicyRequest{Operation: "set", Owner: "owner", DenyCidrs: []string{"::/0"}})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("policy lock ignored cancellation", err)
		}
	case <-time.After(time.Second):
		<-s.mu
		t.Fatal("policy lock exceeded deadline")
	}
	<-s.mu
	if out := policyCall(t, s, "get", "owner", "", nil, nil); out.Configured {
		t.Fatal("timed out mutation committed", out)
	}
}
func TestIPPolicyStoreInheritanceOwnershipAndRestart(t *testing.T) {
	s, db := fixture(t)
	out := policyCall(t, s, "get", "owner", "api", nil, nil)
	if !out.Inherited || out.Configured {
		t.Fatal(out)
	}
	policyCall(t, s, "set", "owner", "", []string{"192.0.2.99/24"}, []string{"192.0.2.42/32"})
	out = policyCall(t, s, "get", "owner", "api", nil, nil)
	if !out.Inherited || !out.Configured || !ippolicy.Allowed("192.0.2.1", out.AllowCidrs, out.DenyCidrs) || ippolicy.Allowed("192.0.2.42", out.AllowCidrs, out.DenyCidrs) {
		t.Fatal(out)
	}
	policyCall(t, s, "set", "owner", "api", nil, nil)
	out = policyCall(t, s, "get", "owner", "api", nil, nil)
	if out.Inherited || !out.Configured || !ippolicy.Allowed("198.51.100.1", out.AllowCidrs, out.DenyCidrs) {
		t.Fatal("empty endpoint override", out)
	}
	policyCall(t, s, "set", "owner", "api", []string{"2001:db8::/32"}, nil)
	policyCall(t, s, "set", "other", "api", nil, []string{"::/0"})
	out = policyCall(t, s, "get", "other", "api", nil, nil)
	if len(out.AllowCidrs) != 0 || len(out.DenyCidrs) != 1 {
		t.Fatal("cross owner policy leaked", out)
	}
	restarted, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	out = policyCall(t, restarted, "get", "owner", "api", nil, nil)
	if out.Inherited || len(out.AllowCidrs) != 1 || out.AllowCidrs[0] != "2001:db8::/32" {
		t.Fatal("restart lost policy", out)
	}
	out = policyCall(t, restarted, "delete", "owner", "api", nil, nil)
	if !out.Inherited || out.AllowCidrs[0] != "192.0.2.0/24" {
		t.Fatal(out)
	}
	out = policyCall(t, restarted, "delete", "owner", "", nil, nil)
	if out.Configured || len(out.AllowCidrs) > 0 || len(out.DenyCidrs) > 0 {
		t.Fatal(out)
	}
	out = policyCall(t, restarted, "get", "other", "api", nil, nil)
	if len(out.DenyCidrs) != 1 {
		t.Fatal("delete altered another owner", out)
	}
}
func TestIPPolicyStoreValidationCapacityRateAndCorruption(t *testing.T) {
	s, db := fixture(t)
	s.maxOwnerResources = 2
	s.maxGrants = 4
	s.maxSharingMutations = 4
	for _, in := range []*pb.IPPolicyRequest{
		nil, {Operation: "set", Owner: ""}, {Operation: "set", Owner: "owner", Endpoint: "bad/name"},
		{Operation: "unknown", Owner: "owner"}, {Operation: "get", Owner: "owner", AllowCidrs: []string{"0.0.0.0/0"}},
		{Operation: "set", Owner: "owner", AllowCidrs: []string{"invalid"}},
		{Operation: "set", Owner: "owner", DenyCidrs: make([]string, 65)},
	} {
		if _, err := s.IPPolicy(context.Background(), in); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("validation: %v", err)
		}
	}
	policyCall(t, s, "set", "owner", "one", nil, nil)
	policyCall(t, s, "set", "owner", "two", nil, nil)
	if _, err := s.IPPolicy(context.Background(), &pb.IPPolicyRequest{Operation: "set", Owner: "owner", Endpoint: "three"}); !errors.Is(err, ErrCapacity) {
		t.Fatal("owner cap", err)
	}
	policyCall(t, s, "set", "owner", "", nil, nil)    // default has an independent slot
	policyCall(t, s, "set", "owner", "one", nil, nil) // update existing scope at capacity
	if _, err := s.IPPolicy(context.Background(), &pb.IPPolicyRequest{Operation: "delete", Owner: "owner", Endpoint: "one"}); !errors.Is(err, ErrSharingRate) {
		t.Fatal("mutation rate", err)
	}
	policyCall(t, s, "set", "other", "", nil, nil)
	if _, err := s.IPPolicy(context.Background(), &pb.IPPolicyRequest{Operation: "set", Owner: "third"}); !errors.Is(err, ErrCapacity) {
		t.Fatal("global cap", err)
	}
	if _, err := db.Exec(`UPDATE ip_policies SET data='invalid' WHERE owner='owner' AND endpoint='one'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IPPolicy(context.Background(), &pb.IPPolicyRequest{Operation: "get", Owner: "owner", Endpoint: "one"}); err == nil {
		t.Fatal("corruption opened policy")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.IPPolicy(ctx, &pb.IPPolicyRequest{Operation: "get", Owner: "owner"}); err == nil {
		t.Fatal("cancelled authority opened policy")
	}
}
