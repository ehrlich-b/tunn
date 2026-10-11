package domains

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestEdgeDomainRenewalFailureRechecksDNS(t *testing.T) {
	for _, changeDNS := range []bool{false, true} {
		t.Run(fmt.Sprintf("DNS changes=%v", changeDNS), func(t *testing.T) {
			r, dns, _ := domainFixture(t, nil)
			d := addDomain(t, r, "work.example.com", "site", "one")
			dns.records[d.Name] = d.CnameTarget
			r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
				cert, key := fakeCert(t, d.Name, r.now())
				return cert, key, nil
			})
			if _, err := r.Verify(context.Background(), d); err != nil {
				t.Fatal(err)
			}
			now := r.now().Add(61 * 24 * time.Hour)
			r.now = func() time.Time { return now }
			r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
				if changeDNS {
					dns.records[d.Name] = "new-owner.example.com"
				}
				return nil, nil, fmt.Errorf("fixture ACME unavailable")
			})
			if err := r.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			_, err := r.Certificate(context.Background(), d)
			if (err != nil) != changeDNS {
				t.Fatalf("renewal fallback served certificate after DNS change=%v: %v", changeDNS, err)
			}
		})
	}
}
