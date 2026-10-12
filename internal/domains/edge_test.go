package domains

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func edgeCertificate(t *testing.T, name string, now time.Time, change func(*x509.Certificate)) ([]byte, []byte) {
	t.Helper()
	certPEM, keyPEM := fakeCert(t, name, now)
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	change(cert)
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, cert.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM
}

func TestEdgeDomainCertificateValidity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
		valid  bool
	}{
		{"valid", func(*x509.Certificate) {}, true},
		{"valid at not-before", func(c *x509.Certificate) { c.NotBefore = c.NotBefore.Add(time.Hour) }, true},
		{"future not-before", func(c *x509.Certificate) { c.NotBefore = c.NotBefore.Add(2 * time.Hour) }, false},
		{"at expiry", func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(time.Hour) }, false},
		{"expired", func(c *x509.Certificate) { c.NotAfter = c.NotBefore }, false},
		{"multiple SANs", func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "other.example.com") }, false},
		{"wildcard SAN", func(c *x509.Certificate) { c.DNSNames = []string{"*.example.com"} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, dns, _ := domainFixture(t, nil)
			d := addDomain(t, r, "work.example.com", "site", "one")
			dns.records[d.Name] = d.CnameTarget
			cert, key := edgeCertificate(t, d.Name, r.now(), tc.change)
			r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) { return cert, key, nil })
			_, err := r.Verify(context.Background(), d)
			if (err == nil) != tc.valid {
				t.Fatalf("Verify error=%v, valid=%v", err, tc.valid)
			}
			_, err = r.Certificate(context.Background(), d)
			if (err == nil) != tc.valid {
				t.Fatalf("Certificate error=%v, valid=%v", err, tc.valid)
			}
		})
	}
	for _, kind := range []string{"malformed certificate", "malformed key", "mismatched key"} {
		t.Run(kind, func(t *testing.T) {
			r, dns, _ := domainFixture(t, nil)
			d := addDomain(t, r, "work.example.com", "site", "one")
			dns.records[d.Name] = d.CnameTarget
			cert, key := fakeCert(t, d.Name, r.now())
			switch kind {
			case "malformed certificate":
				cert = []byte("invalid PEM")
			case "malformed key":
				key = []byte("invalid PEM")
			case "mismatched key":
				_, key = fakeCert(t, d.Name, r.now())
			}
			r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) { return cert, key, nil })
			if _, err := r.Verify(context.Background(), d); err == nil {
				t.Fatal("invalid issuer material accepted")
			}
			if _, err := r.Route(context.Background(), d); err == nil {
				t.Fatal("invalid issuer material activated route")
			}
		})
	}
}

func TestEdgeDomainChallengeLifecycle(t *testing.T) {
	for _, revoke := range []string{"expiry", "delete", "downgrade", "reservation"} {
		t.Run(revoke, func(t *testing.T) {
			r, dns, db := domainFixture(t, nil)
			d := addDomain(t, r, "work.example.com", "site", "one")
			dns.records[d.Name] = d.CnameTarget
			r.issuer = issuerFunc(func(ctx context.Context, name string, present PresentChallenge) ([]byte, []byte, error) {
				for _, token := range []string{"", "a/b", `a\b`, strings.Repeat("a", 257)} {
					if _, err := present(ctx, token, "proof"); err == nil {
						t.Fatalf("accepted invalid challenge token %q", token)
					}
				}
				oldCleanup, err := present(ctx, "old-token", "old-proof")
				if err != nil {
					return nil, nil, err
				}
				cleanup, err := present(ctx, "current-token", "current-proof")
				if err != nil {
					return nil, nil, err
				}
				defer cleanup()
				oldCleanup()
				q := &pb.ChallengeRequest{Name: strings.ToUpper(name) + ".", Token: "current-token"}
				response, err := r.Challenge(ctx, q)
				if err != nil || response.Body != "current-proof" {
					t.Fatalf("current challenge removed by stale cleanup: %v %v", response, err)
				}
				for _, q := range []*pb.ChallengeRequest{{Name: name, Token: "old-token"}, {Name: "other.example.com", Token: "current-token"}} {
					if _, err := r.Challenge(ctx, q); status.Code(err) != codes.NotFound {
						t.Fatalf("challenge escaped its host/token: %v", err)
					}
				}
				switch revoke {
				case "expiry":
					now := r.now().Add(10 * time.Minute)
					r.now = func() time.Time { return now }
				case "delete":
					_, err = r.Delete(ctx, d)
				case "downgrade":
					_, err = db.Exec("UPDATE accounts SET plan='free' WHERE id='one'")
				case "reservation":
					_, err = db.Exec("UPDATE reserved_subdomains SET account_id='two' WHERE subdomain='site'")
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := r.Challenge(ctx, q); status.Code(err) != codes.NotFound {
					t.Fatalf("revoked challenge served: %v", err)
				}
				return nil, nil, fmt.Errorf("fixture order ended")
			})
			_, _ = r.Verify(context.Background(), d)
			var count int
			if err := db.QueryRow("SELECT count(*) FROM domain_challenges").Scan(&count); err != nil || count != 0 {
				t.Fatalf("challenge cleanup count=%d: %v", count, err)
			}
		})
	}
}

func TestEdgeDomainCertificateKeyBindingAndRestart(t *testing.T) {
	r, dns, db := domainFixture(t, nil)
	d := addDomain(t, r, "work.example.com", "site", "one")
	dns.records[d.Name] = d.CnameTarget
	cert, key := fakeCert(t, d.Name, r.now())
	r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) { return cert, key, nil })
	ctx := context.Background()
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := db.QueryRow("SELECT key FROM custom_domains WHERE name=?", d.Name).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, key) {
		t.Fatal("private certificate key persisted as plaintext")
	}
	for _, secret := range [][]byte{fixtureKey, []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")} {
		restarted, err := New(db, "relay.test", secret, dns, nil)
		if err != nil {
			t.Fatal(err)
		}
		restarted.now = r.now
		pair, err := restarted.Certificate(ctx, d)
		if bytes.Equal(secret, fixtureKey) {
			if err != nil || !bytes.Equal(pair.KeyPem, key) || !bytes.Equal(pair.CertificatePem, cert) {
				t.Fatalf("restart lost certificate: %v %v", pair, err)
			}
		} else if err == nil {
			t.Fatal("wrong encryption secret decrypted key")
		}
	}
	if _, err := r.decrypt("other.example.com", sealed); err == nil {
		t.Fatal("encrypted key transferred to another domain")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := db.Exec("UPDATE custom_domains SET key=? WHERE name=?", sealed, d.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Certificate(ctx, d); err == nil {
		t.Fatal("corrupt key served")
	}
}

func TestEdgeDomainVerificationGateHonorsCancellation(t *testing.T) {
	r, dns, _ := domainFixture(t, nil)
	d := addDomain(t, r, "work.example.com", "site", "one")
	dns.records[d.Name] = d.CnameTarget
	started, release := make(chan struct{}), make(chan struct{})
	r.issuer = issuerFunc(func(ctx context.Context, _ string, _ PresentChallenge) ([]byte, []byte, error) {
		close(started)
		select {
		case <-release:
			return nil, nil, fmt.Errorf("fixture order ended")
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	})
	firstCtx, cancelFirst := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelFirst()
	done := make(chan error, 1)
	go func() { _, err := r.Verify(firstCtx, d); done <- err }()
	select {
	case <-started:
	case <-firstCtx.Done():
		t.Fatal("first order did not start")
	}
	secondCtx, cancelSecond := context.WithCancel(context.Background())
	cancelSecond()
	if _, err := r.Verify(secondCtx, d); err != context.Canceled {
		t.Fatalf("queued verification did not honor cancellation: %v", err)
	}
	close(release)
	if err := <-done; status.Code(err) != codes.Unavailable {
		t.Fatalf("fixture issuance error=%v", err)
	}
	// An ended order releases the gate, but its failed attempt still enforces
	// the shared retry delay. Advance the fixture clock past that delay.
	nextAttempt := r.now().Add(time.Minute)
	r.now = func() time.Time { return nextAttempt }
	r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
		cert, key := fakeCert(t, d.Name, r.now())
		return cert, key, nil
	})
	if _, err := r.Verify(firstCtx, d); err != nil {
		t.Fatal("ended order retained verification gate", err)
	}
}

func TestEdgeDomainRouteLeaseBoundaryAndRefresh(t *testing.T) {
	r, dns, _ := domainFixture(t, nil)
	d := addDomain(t, r, "work.example.com", "site", "one")
	dns.records[d.Name] = strings.ToUpper(d.CnameTarget) + "."
	issues := 0
	r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
		issues++
		cert, key := fakeCert(t, d.Name, r.now())
		return cert, key, nil
	})
	ready, err := r.Verify(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(ready.VerifiedUntil-1, 0)
	r.now = func() time.Time { return now }
	if _, err := r.Route(context.Background(), d); err != nil {
		t.Fatal("lease expired one second early", err)
	}
	now = now.Add(time.Second)
	if _, err := r.Certificate(context.Background(), d); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("certificate served at expired DNS lease", err)
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Route(context.Background(), d); err != nil || issues != 1 {
		t.Fatalf("healthy refresh lost route or needlessly issued: %v issues=%d", err, issues)
	}
}
