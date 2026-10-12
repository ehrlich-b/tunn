package domains

import (
	"context"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"testing"
	"time"
)

func TestR3ReservationLossDuringFailedRenewalReturnsOldKey(t *testing.T) {
	r, _, d := wildcardFixture(t)
	ctx := context.Background()
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	r.issuer = issuerFunc(func(_ context.Context, name string, _ PresentChallenge) ([]byte, []byte, error) {
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	if _, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"}); err != nil {
		t.Fatal(err)
	}
	now := r.now().Add(61 * 24 * time.Hour)
	r.now = func() time.Time { return now }
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	r.issuer = issuerFunc(func(_ context.Context, _ string, _ PresentChallenge) ([]byte, []byte, error) {
		accounts := store.NewAccountStore(r.db)
		if err := accounts.ReleaseSubdomain("one", "dashboard"); err != nil {
			t.Fatal(err)
		}
		if err := accounts.ReserveSubdomain("two", "dashboard"); err != nil {
			t.Fatal(err)
		}
		return nil, nil, fmt.Errorf("bounded fixture renewal failure")
	})
	pair, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"})
	if err == nil && len(pair.KeyPem) > 0 {
		t.Fatal("failed renewal returned cached key after app reservation changed owner")
	}
}
