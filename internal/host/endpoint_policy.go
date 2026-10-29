package host

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/trafficpolicy"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Bound CPU-intensive password verification across all endpoints in a relay.
// A full pool rejects immediately rather than accumulating waiting requests.
var basicAuthSlots = make(chan struct{}, 4)

func (p *ProxyServer) handleEndpointPolicyAPI(w http.ResponseWriter, r *http.Request, endpoint string) {
	w.Header().Set("Cache-Control", "no-store")
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Platform origin required", 403)
		return
	}
	a := p.sharingOwner(w, r, false)
	if a == nil {
		return
	}
	backend, ok := p.meter.(metering.PolicyBackend)
	if !ok {
		http.Error(w, "Policy authority unavailable", 503)
		return
	}
	in := &pb.EndpointPolicyRequest{Owner: a.ID, Endpoint: endpoint}
	switch r.Method {
	case http.MethodGet:
		in.Operation = "get"
	case http.MethodPut, http.MethodDelete:
		if !p.requireAuthOrigin(w, r, true) {
			return
		}
		if r.Method == http.MethodDelete {
			in.Operation = "clear"
		} else {
			data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, trafficpolicy.MaxJSONBytes))
			if err != nil {
				http.Error(w, "Policy JSON exceeds size limit", 400)
				return
			}
			policy, err := trafficpolicy.Decode(data)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			in.PolicyJson, _ = json.Marshal(policy)
			in.Operation = "set"
		}
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "Use GET, PUT or DELETE", 405)
		return
	}
	out, err := backend.EndpointPolicy(r.Context(), in)
	if err != nil {
		switch {
		case status.Code(err) == codes.NotFound:
			http.Error(w, "Endpoint not found", 404)
		case status.Code(err) == codes.InvalidArgument:
			http.Error(w, "Invalid endpoint policy", 400)
		case errors.Is(err, metering.ErrSharingRate):
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Policy mutation rate reached", 429)
		default:
			http.Error(w, "Policy authority unavailable", 503)
		}
		return
	}
	policy, err := trafficpolicy.Decode(out.PolicyJson)
	if err != nil {
		http.Error(w, "Policy authority returned invalid policy", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(policy)
}

// Every account-managed HTTP resource consults the current policy authority.
// Legacy/self-hosted endpoints without a resource UUID cannot carry a policy.
func (p *ProxyServer) applyEndpointPolicy(w http.ResponseWriter, r *http.Request, t *TunnelConnection, s *ingressMeter) (*http.Request, bool) {
	resourceID := t.ResourceID
	if t.PolicyResourceID != "" {
		resourceID = t.PolicyResourceID
	}
	if resourceID == "" || t.EndpointProtocol == "tcp" {
		return r, true
	}
	backend, ok := p.meter.(metering.PolicyBackend)
	fail := func(reason string) (*http.Request, bool) {
		s.reason = reason
		w.Header().Set("Tunn-Limit-Reason", reason)
		http.Error(w, "Policy authority unavailable", 503)
		return r, false
	}
	if !ok {
		return fail("policy_unavailable")
	}
	peer, _ := p.forwardingPeer(r)
	if ip, err := netip.ParseAddr(peer); err == nil {
		peer = ip.Unmap().String()
	}
	parent := r.Context()
	if admission, _ := parent.Value(appAdmissionKey{}).(context.Context); admission != nil {
		parent = admission
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	out, err := backend.EndpointPolicy(ctx, &pb.EndpointPolicyRequest{Operation: "admit", Owner: s.event.Owner, Endpoint: t.TunnelID, ResourceId: resourceID, ClientIp: peer, GrantId: s.event.GrantId})
	if err != nil || out == nil || out.Decision == nil {
		return fail("policy_unavailable")
	}
	if !out.Decision.Allowed {
		s.reason = out.Decision.Reason
		w.Header().Set("Tunn-Limit-Reason", s.reason)
		if out.Decision.Status == http.StatusForbidden {
			http.Error(w, "Endpoint credential no longer valid", http.StatusForbidden)
		} else {
			w.Header().Set("Retry-After", strconv.FormatInt(max(1, out.Decision.RetryAfter), 10))
			http.Error(w, "Endpoint rate limit reached", http.StatusTooManyRequests)
		}
		return r, false
	}
	policy, err := trafficpolicy.Decode(out.PolicyJson)
	if err != nil {
		return fail("policy_unavailable")
	}
	if basic := policy.BasicAuth; basic != nil {
		user, password, valid := r.BasicAuth()
		challenge := func() (*http.Request, bool) {
			s.reason = "policy_basic_auth"
			w.Header().Set("WWW-Authenticate", `Basic realm="tunn", charset="UTF-8"`)
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return r, false
		}
		if !valid || len(r.Header.Values("Authorization")) != 1 || len(password) > 72 {
			return challenge()
		}
		select {
		case basicAuthSlots <- struct{}{}:
		default:
			s.reason = "policy_basic_auth_busy"
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "Authentication temporarily unavailable", http.StatusServiceUnavailable)
			return r, false
		}
		// Keep username and password failures indistinguishable for valid inputs.
		passwordOK := bcrypt.CompareHashAndPassword([]byte(basic.PasswordHash), []byte(password)) == nil
		<-basicAuthSlots
		if subtle.ConstantTimeCompare([]byte(user), []byte(basic.Username)) != 1 || !passwordOK {
			return challenge()
		}
		r = r.Clone(r.Context())
		r.Header = r.Header.Clone()
		r.Header.Del("Authorization")
	}
	// A connection-nominated application header must not discard an owner's
	// configured field at the target's hop-by-hop sanitation boundary.
	for _, token := range strings.Split(strings.Join(r.Header.Values("Connection"), ","), ",") {
		for _, edits := range [][]trafficpolicy.Header{policy.Headers.Add, policy.Headers.Rewrite} {
			for _, edit := range edits {
				if strings.EqualFold(strings.TrimSpace(token), edit.Name) {
					http.Error(w, "Connection header conflicts with endpoint policy", 400)
					s.reason = "policy_header_conflict"
					return r, false
				}
			}
		}
	}
	return policy.Apply(r), true
}
