package host

import (
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestDeviceAdmissionUsesAuthenticatedPeer(t *testing.T) {
	p := durableFixture(t)
	for i := 0; i <= deviceCodeRateMaxCount; i++ {
		r := httptest.NewRequest("POST", "https://tunn.test/api/device/code", nil)
		r.RemoteAddr = "192.0.2.10:4321"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
		r.Header.Set("X-Real-IP", fmt.Sprintf("203.0.113.%d", i+1))
		w := httptest.NewRecorder()
		p.handleDeviceCode(w, r)
		want := 200
		if i == deviceCodeRateMaxCount {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("request %d: status %d, want %d", i, w.Code, want)
		}
	}
}

func TestDeviceAdmissionRelayPeerNormalization(t *testing.T) {
	p := durableFixture(t)
	p.config.NodeSecret = "fixture-cluster"
	for i := 0; i < deviceCodeRateMaxCount; i++ {
		r := httptest.NewRequest("POST", "https://tunn.test/api/device/code", nil)
		r.RemoteAddr = "192.0.2.200:1234"
		r.Header.Set(relayForwardedFor, "::ffff:192.0.2.10")
		r.Header.Set(relayForwardedProto, "https")
		r.Header.Set(relayForwardedSignature, p.forwardingSignature(r.Host, "::ffff:192.0.2.10", "https"))
		w := httptest.NewRecorder()
		p.handleDeviceCode(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	r := httptest.NewRequest("POST", "https://tunn.test/api/device/code", nil)
	r.RemoteAddr = "192.0.2.10:4321"
	r.Header.Set(relayForwardedFor, "198.51.100.9")
	r.Header.Set(relayForwardedProto, "https")
	r.Header.Set(relayForwardedSignature, "invalid")
	w := httptest.NewRecorder()
	p.handleDeviceCode(w, r)
	if w.Code != 429 {
		t.Fatal("equivalent ingress peer got another allowance", w.Code)
	}
}
