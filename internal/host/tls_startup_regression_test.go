package host

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Reproduces the shared TLS configuration defect inherited from 110485c.
// Both protocols must negotiate successfully without mutating the template.
func TestReviewTLSListenerConfigurationIsolation(t *testing.T) {
	p, client, _ := opsProxy(t)
	p.tlsConfig.NextProtos = nil
	original := p.tlsConfig.Clone()
	cancel, done := opsStart(t, p)
	opsWaitHealth(t, p, client, "/readyz", 200)

	check := func(client *http.Client, addr string, major int) {
		t.Helper()
		request, err := http.NewRequest("GET", "https://"+addr+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "tunn.test"
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != 200 || response.ProtoMajor != major {
			t.Fatalf("listener negotiated %s, status %d; want HTTP/%d", response.Proto, response.StatusCode, major)
		}
	}
	check(client, p.HTTP2Addr, 2)
	transport := &http3.Transport{TLSClientConfig: client.Transport.(*http.Transport).TLSClientConfig.Clone()}
	defer transport.Close()
	check(&http.Client{Transport: transport, Timeout: 3 * time.Second}, p.HTTP3Addr, 3)
	cancel()
	if err := opsWaitStopped(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Compare after shutdown so this assertion itself does not race with startup.
	if !reflect.DeepEqual(p.tlsConfig.NextProtos, original.NextProtos) || p.tlsConfig.PreferServerCipherSuites != original.PreferServerCipherSuites {
		t.Errorf("listener startup mutated shared TLS template: protocols=%v, cipher preference=%t", p.tlsConfig.NextProtos, p.tlsConfig.PreferServerCipherSuites)
	}
	opsAssertReleased(t, p)
}
