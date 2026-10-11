package sshfront

import (
	"fmt"
	"testing"
)

func TestSSHConsumerTransportBudgets(t *testing.T) {
	for _, kind := range []string{"key", "ip", "account"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _ := reviewForwardClient(t, func(s *Server, id Identity) {
				limit := 10
				if kind == "ip" {
					limit = 30
				}
				if kind == "account" {
					limit = 20
				}
				for n := 0; n < limit; n++ {
					other := id
					if kind != "key" {
						other.Fingerprint = fmt.Sprint(n)
					}
					if kind != "ip" {
						other.IP = fmt.Sprint(n)
					}
					if kind != "account" {
						other.Email = fmt.Sprint(n) + "@example.com"
					}
					release, err := s.acquireBudget(other, "transport:")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(release)
				}
			})
			stream, err := c.Dial("tcp", "private:22")
			if err == nil {
				stream.Close()
				t.Fatalf("consumer transport bypassed per-%s limit", kind)
			}
		})
	}
}

func TestSSHCanonicalAccountBudgetCannotSplitAcrossEmails(t *testing.T) {
	s := &Server{budgets: map[string]*budget{}}
	for n := 0; n < 20; n++ {
		id := Identity{Fingerprint: fmt.Sprint(n), Email: fmt.Sprint(n) + "@example.com", IP: fmt.Sprint(n), AccountID: "canonical-account"}
		release, err := s.acquire(id)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
	}
	if release, err := s.acquire(Identity{Fingerprint: "other", Email: "other@example.com", IP: "other", AccountID: "canonical-account"}); err == nil {
		release()
		t.Fatal("alias escaped canonical account channel budget")
	}
}
