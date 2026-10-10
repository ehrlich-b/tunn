package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestForwardedHTTPHeadersRejectSpoofingAndStripCredentials(t *testing.T) {
	proxy := &ProxyServer{config: &config.Config{NodeSecret: "fixture-secret"}}
	request := httptest.NewRequest(http.MethodGet, "https://claw.tunn.test:8443/a", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("Origin", "https://claw.tunn.test:8443")
	request.Header.Set("Authorization", "Bearer application-token")
	request.Header.Set("Tunn-Authorization", "Bearer outer-token")
	request.Header.Set("Cookie", "tunn_auth=secret; tunn_session=legacy; app=kept")
	request.Header.Set("X-Forwarded-For", "spoofed")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Forwarded-Host", "spoofed")
	request.Header.Set("Forwarded", "for=spoofed")
	request.Header.Set(relayForwardedFor, "198.51.100.7")
	request.Header.Set(relayForwardedProto, "http")
	request.Header.Set(relayForwardedSignature, "forged")
	headers := proxy.forwardedHTTPHeaders(request)
	for name, want := range map[string]string{"Host": "claw.tunn.test:8443", "Origin": "https://claw.tunn.test:8443", "X-Forwarded-For": "192.0.2.10", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "claw.tunn.test:8443", "Authorization": "Bearer application-token", "Cookie": "app=kept"} {
		if headers[name] != want {
			t.Errorf("%s=%q; want %q", name, headers[name], want)
		}
	}
	for _, name := range []string{"Tunn-Authorization", "Forwarded", relayForwardedFor, relayForwardedProto, relayForwardedSignature} {
		if headers[name] != "" {
			t.Errorf("leaked %s", name)
		}
	}
	// A signed cluster hop preserves the ingress peer and scheme. Changing the
	// public authority invalidates it, preventing reuse across endpoints.
	request.Header.Set(relayForwardedSignature, proxy.forwardingSignature(request.Host, "198.51.100.7", "http"))
	headers = proxy.forwardedHTTPHeaders(request)
	if headers["X-Forwarded-For"] != "198.51.100.7" || headers["X-Forwarded-Proto"] != "http" {
		t.Fatalf("cluster metadata lost: %v", headers)
	}
	request.Host = "other.tunn.test"
	if proxy.forwardedHTTPHeaders(request)["X-Forwarded-For"] != "192.0.2.10" {
		t.Fatal("cross-endpoint cluster signature accepted")
	}
}

func TestForwardedHTTPLegacyPath(t *testing.T) {
	stream := &mockWebProxyStream{}
	tunnel := &TunnelConnection{Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse)}
	respondToForwardedRequest(t, stream, tunnel)
	request := httptest.NewRequest(http.MethodGet, "https://claw.tunn.test/a", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("Origin", "https://claw.tunn.test")
	recorder := httptest.NewRecorder()
	if err := (&ProxyServer{}).proxyHTTPOverGRPC(recorder, request, tunnel); err != nil {
		t.Fatal(err)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	headers := stream.sentMsgs[0].GetHttpRequest().Headers
	if headers["Host"] != "claw.tunn.test" || headers["X-Forwarded-For"] != "192.0.2.10" || headers["Origin"] != "https://claw.tunn.test" || headers["X-Forwarded-Proto"] != "https" {
		t.Fatalf("legacy headers: %v", headers)
	}
}
