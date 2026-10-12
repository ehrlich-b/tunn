package host

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestReviewSlowDiscoveryBlocksOtherOrg(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	if _, err := f.p.orgProvider(context.Background(), f.org); err != nil {
		t.Fatal(err)
	}
	slowOrg := f.org
	slowOrg.ID, slowOrg.Issuer = "slow", "https://slow.example"
	base := f.p.orgOIDCHTTPClient.Transport
	entered, release := make(chan struct{}), make(chan struct{})
	var fetches atomic.Int64
	f.p.orgOIDCHTTPClient = &http.Client{Transport: securityRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "slow.example" {
			if fetches.Add(1) == 1 {
				close(entered)
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return nil, fmt.Errorf("simulated unavailable org")
		}
		return base.RoundTrip(r)
	})}
	slowDone := make(chan struct{})
	go func() {
		defer close(slowDone)
		_, _ = f.p.orgProvider(context.Background(), slowOrg)
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	fastDone := make(chan error, 1)
	go func() { _, err := f.p.orgProvider(ctx, f.org); fastDone <- err }()

	defer func() { close(release); <-slowDone }()
	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatal("cached provider failed", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("cached org blocked behind slow discovery")
	}
	// A waiter for the same policy obeys its own context and shares one fetch.
	ctx, cancelWait := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelWait()
	waitDone := make(chan error, 1)
	go func() { _, err := f.p.orgProvider(ctx, slowOrg); waitDone <- err }()
	select {
	case err := <-waitDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("wait ignored cancellation", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("waiter ignored deadline")
	}
	if fetches.Load() != 1 {
		t.Fatal("concurrent discovery was not coalesced", fetches.Load())
	}
}

func TestOrgDiscoveryFailureBackoff(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	var fetches atomic.Int64
	f.p.orgOIDCHTTPClient = &http.Client{Transport: securityRoundTripper(func(r *http.Request) (*http.Response, error) {
		fetches.Add(1)
		return nil, fmt.Errorf("issuer unavailable")
	})}
	for i := 0; i < 10; i++ {
		if _, err := f.p.orgProvider(context.Background(), f.org); err == nil {
			t.Fatal("unavailable issuer accepted")
		}
	}
	if fetches.Load() != 1 {
		t.Fatal("failed discovery hammered issuer", fetches.Load())
	}
	f.p.orgProvidersMu.Lock()
	f.p.orgProviderInits[f.org.PolicyDigest()].retryAfter = time.Now().Add(-time.Second)
	f.p.orgProvidersMu.Unlock()
	if _, err := f.p.orgProvider(context.Background(), f.org); err == nil {
		t.Fatal("issuer accepted")
	}
	if fetches.Load() != 2 {
		t.Fatal("discovery did not retry after backoff")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.p.orgProvider(ctx, f.org); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled caller ignored", err)
	}
}
