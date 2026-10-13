package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/trafficpolicy"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestAllPolicyWebhookIncomingSignature(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		for _, edit := range []string{"remove", "rewrite"} {
			t.Run(fmt.Sprintf("buffered=%t/%s", buffered, edit), func(t *testing.T) {
				s := startHookStack(t, "github", buffered, false, true)
				body := []byte("bounded signature composition fixture")
				signature := webhookHeaders("github", body, time.Now().Unix()).Get("X-Hub-Signature-256")
				policy := trafficpolicy.Policy{}
				if edit == "remove" {
					policy.Headers.Remove = []string{"X-Hub-Signature-256"}
				} else {
					policy.Headers.Rewrite = []trafficpolicy.Header{{Name: "X-Hub-Signature-256", Value: signature}}
				}
				data, _ := json.Marshal(policy)
				relayPolicy(t, s.proxy, s.tunnel, string(data))
				for _, valid := range []bool{false, true} {
					r := httptest.NewRequest("POST", "https://hook.tunn.test/webhook?raw=1", bytes.NewReader(body))
					r.Header.Set("Cookie", "app=keep")
					r.Header.Set("Authorization", "Bearer application-fixture")
					if valid {
						r.Header.Set("X-Hub-Signature-256", signature)
					}
					before := s.hits.Load()
					w := httptest.NewRecorder()
					s.proxy.handleWebProxy(w, r)
					want := http.StatusUnauthorized
					if valid {
						want = http.StatusAccepted
					}
					if w.Code != want {
						t.Fatalf("incoming valid=%t: status=%d want=%d: %s", valid, w.Code, want, w.Body)
					}
					if valid && (s.hits.Load() != before+1 || !bytes.Equal(w.Body.Bytes(), body)) {
						t.Fatal("valid raw delivery was changed")
					}
					if !valid && s.hits.Load() != before {
						t.Fatal("header policy replaced sender verification")
					}
				}
			})
		}
	}
}

func TestAllInspectorPolicyReplayInputs(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	out, err := f.p.sharingBackend().Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: f.tunnel.AccountID, Endpoint: "api", Mode: "private"})
	if err != nil {
		t.Fatal(err)
	}
	f.tunnel.ResourceID = out.Resources[0].Id
	relayPolicy(t, f.p, f.tunnel, `{"headers":{"add":[{"name":"Accept","value":"owner"}]}}`)
	r := httptest.NewRequest("POST", "https://api.tunn.test/hooks?token=QUERY_SENTINEL", strings.NewReader("BODY_PAYLOAD_SENTINEL"))
	r.AddCookie(f.cookie)
	r.Header.Add("Cookie", "app_sid=COOKIE_SENTINEL")
	r.Header.Set("Authorization", "Bearer HEADER_SENTINEL")
	r.Header.Set("Accept", "visitor")
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	if w.Code != 202 {
		t.Fatalf("original=%d %s", w.Code, w.Body)
	}
	event := f.tunnel.inspectionHistory().Snapshot()[0]
	if event.Headers["Accept"] != "visitor" {
		t.Fatalf("history retained edited headers: %v", event.Headers)
	}
	action := f.prepare(t, event)
	w = f.call("POST", fmt.Sprintf("/api/inspector/api/requests/%d/replay", event.ID), f.replayInput(event, action), f.cookie, nil)
	if w.Code != 200 || len(f.deliveries) != 2 {
		t.Fatalf("replay=%d %s", w.Code, w.Body)
	}
	for _, delivery := range f.deliveries {
		if delivery.Headers["Accept"] != "visitor, owner" {
			t.Fatalf("policy applied repeatedly: %v", delivery.Headers)
		}
	}
	// Replay must consult the latest rate policy rather than reuse admission.
	relayPolicy(t, f.p, f.tunnel, `{"rate_limits":{"per_account":{"requests_per_minute":1,"burst":1}}}`)
	f.seed(t)
	action = f.prepare(t, event)
	before := len(f.deliveries)
	w = f.call("POST", fmt.Sprintf("/api/inspector/api/requests/%d/replay", event.ID), f.replayInput(event, action), f.cookie, nil)
	if w.Code != 429 || len(f.deliveries) != before {
		t.Fatalf("rate-limited replay=%d %s", w.Code, w.Body)
	}
}

type allDeadlineLedger struct {
	*metering.Store
	deadlines []time.Time
}

func (b *allDeadlineLedger) IPPolicy(ctx context.Context, in *mp.IPPolicyRequest) (*mp.IPPolicy, error) {
	d, _ := ctx.Deadline()
	b.deadlines = append(b.deadlines, d)
	return b.Store.IPPolicy(ctx, in)
}

func (b *allDeadlineLedger) EndpointPolicy(ctx context.Context, in *mp.EndpointPolicyRequest) (*mp.EndpointPolicyResponse, error) {
	d, _ := ctx.Deadline()
	b.deadlines = append(b.deadlines, d)
	return b.Store.EndpointPolicy(ctx, in)
}

func TestAllAppPoliciesShareAdmissionDeadline(t *testing.T) {
	p, tunnel, ledger, _ := policyRelay(t, false)
	backend := &allDeadlineLedger{Store: ledger}
	p.meter = backend
	admission, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := admission.Deadline()
	r := relayRequest(relayJWT(t, p, "owner@example.com"), "")
	r = r.WithContext(context.WithValue(r.Context(), appAdmissionKey{}, admission))
	w := httptest.NewRecorder()
	if !p.checkOwnerIPPolicy(w, r, tunnel.AccountID, tunnel.TunnelID) {
		t.Fatalf("IP admission=%d %s", w.Code, w.Body)
	}
	s := newIngressMeter(p, tunnel)
	if _, ok := p.applyEndpointPolicy(w, r, tunnel, s); !ok {
		t.Fatalf("policy admission=%d %s", w.Code, w.Body)
	}
	if len(backend.deadlines) != 2 {
		t.Fatalf("observed %d authorities", len(backend.deadlines))
	}
	for _, observed := range backend.deadlines {
		if !observed.Equal(deadline) {
			t.Fatalf("authority extended shared deadline: %v want %v", observed, deadline)
		}
	}
	// An expired shared budget must fail closed at both authorities.
	cancel()
	if p.checkOwnerIPPolicy(httptest.NewRecorder(), r, tunnel.AccountID, tunnel.TunnelID) {
		t.Fatal("expired IP admission succeeded")
	}
	if _, ok := p.applyEndpointPolicy(httptest.NewRecorder(), r, tunnel, s); ok {
		t.Fatal("expired policy admission succeeded")
	}
}
