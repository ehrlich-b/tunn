package host

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

// The merged policies must compose on both forwarding paths and across relays.
// In particular, a valid sender signature never replaces private access.
func TestParityIPWebhookAdmission(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		for _, private := range []bool{false, true} {
			t.Run(fmt.Sprintf("buffered=%t/private=%t", buffered, private), func(t *testing.T) {
				s := startHookStack(t, "github", buffered, private, true)
				_, err := s.ledger.IPPolicy(context.Background(), &mp.IPPolicyRequest{
					Operation: "set", Owner: s.tunnel.AccountID, Endpoint: "hook",
					AllowCidrs: []string{"192.0.2.0/24"}, DenyCidrs: []string{"192.0.2.42/32"},
				})
				if err != nil {
					t.Fatal(err)
				}
				ingress := &ProxyServer{Domain: s.proxy.Domain,
					config:       &config.Config{Insecure: true, NodeSecret: s.proxy.config.NodeSecret},
					tunnelServer: NewTunnelServer(s.proxy.config, nil, nil, nil),
					tunnelCache:  map[string]string{"hook": s.relay.Listener.Addr().String()}}
				body := []byte(" {\n\"raw\":\"café\"}\r\n\x00\xff")
				for _, remote := range []bool{false, true} {
					for _, kind := range []string{"denied", "denied-signed", "invalid-signature", "valid", "unsigned-private"} {
						if kind == "unsigned-private" && !private {
							continue
						}
						t.Run(fmt.Sprintf("remote=%t/%s", remote, kind), func(t *testing.T) {
							r := httptest.NewRequest("POST", "https://hook.tunn.test/webhook?raw=1", bytes.NewReader(body))
							r.RemoteAddr = "192.0.2.1:9000"
							r.Header = webhookHeaders("github", body, time.Now().Unix())
							r.Header.Set("Cookie", "app=keep")
							r.Header.Set("Authorization", "Bearer application-fixture")
							if private && kind != "unsigned-private" {
								r.Header.Set("Tunn-Authorization", "Bearer tunn_ep_hook-fixture")
							}
							want := http.StatusAccepted
							switch kind {
							case "denied", "denied-signed":
								r.RemoteAddr = "192.0.2.42:9000"
								want = http.StatusForbidden
								if kind == "denied" {
									r.Header.Del("X-Hub-Signature-256")
									r.Header.Del("Tunn-Authorization")
								}
								// Hop-header nomination must not remove trusted peer metadata.
								r.Header.Set("Connection", "Tunn-Relay-For, Tunn-Relay-Proto, Tunn-Relay-Signature")
							case "invalid-signature":
								r.Header.Del("X-Hub-Signature-256")
								want = http.StatusUnauthorized
							case "unsigned-private":
								want = http.StatusUnauthorized
							}
							before := s.hits.Load()
							var reads atomic.Int64
							r.Body = &hookReadCounter{ReadCloser: r.Body, reads: &reads}
							w := httptest.NewRecorder()
							if remote {
								ingress.handleWebProxy(w, r)
							} else {
								s.proxy.handleWebProxy(w, r)
							}
							if w.Code != want {
								t.Fatalf("status=%d, want %d: %s", w.Code, want, w.Body.String())
							}
							if want == http.StatusAccepted {
								if s.hits.Load() != before+1 || !bytes.Equal(w.Body.Bytes(), body) {
									t.Fatal("accepted request lost raw bytes or origin delivery")
								}
							} else if s.hits.Load() != before {
								t.Fatal("denied request reached origin")
							}
							if !remote && (want == http.StatusForbidden || kind == "unsigned-private") && reads.Load() != 0 {
								t.Fatal("policy/auth denial consumed the webhook body")
							}
						})
					}
				}
				// Keep the real authority seam present: no permissive replacement.
				var _ metering.IPPolicyBackend = s.ledger
			})
		}
	}
}
