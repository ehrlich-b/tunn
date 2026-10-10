package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/metering"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

type ingressLimitError struct{ decision *pb.Decision }

func (e *ingressLimitError) Error() string { return e.decision.Reason }

type meterUnavailableError struct{ err error }

func (e *meterUnavailableError) Error() string { return "usage ledger unavailable" }
func (e *meterUnavailableError) Unwrap() error { return e.err }

type meterContextKey struct{}
type ingressMeter struct {
	mu                                        sync.Mutex
	backend                                   metering.Backend
	event                                     *pb.Event
	admitted, closed                          bool
	requestBytes, responseBytes, writtenBytes int64
	reason                                    string
	proxy                                     *ProxyServer
	accountID                                 string
	observing                                 bool
	observationOnce                           sync.Once
}

func newIngressMeter(p *ProxyServer, tunnel *TunnelConnection) *ingressMeter {
	id, _ := generateConnectionID()
	p.operations.active.Add(1)
	return &ingressMeter{backend: p.meter, proxy: p, observing: true, accountID: tunnel.AccountID, event: &pb.Event{RequestId: id, Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Caller: "anonymous", AuthMethod: "none", Allowed: true, Reason: "allowed", StartedAt: time.Now().UnixMilli()}}
}
func (s *ingressMeter) recordError(err error, ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason == "" {
		s.reason = "proxy_failure"
		var limit *ingressLimitError
		if errors.As(err, &limit) {
			s.reason = limit.decision.Reason
		}
	}
	if ctx.Err() != nil && !errors.As(context.Cause(ctx), new(*ingressLimitError)) && !errors.As(context.Cause(ctx), new(*meterUnavailableError)) {
		s.reason = "caller_disconnected"
	}
}
func setMeterHeaders(w http.ResponseWriter, d *pb.Decision) {
	w.Header().Set("Tunn-Requests-Remaining", strconv.FormatInt(d.RequestsRemaining, 10))
	w.Header().Set("Tunn-Bytes-Remaining", strconv.FormatInt(d.BytesRemaining, 10))
	if !d.Allowed {
		w.Header().Set("Tunn-Limit-Reason", d.Reason)
	}
	if d.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(d.RetryAfter, 10))
	}
}
func (s *ingressMeter) admit(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	if s.backend == nil {
		return true
	}
	s.event.ContentLength = r.ContentLength
	d, err := s.backend.Admit(ctx, s.event)
	if err != nil {
		s.reason = "meter_unavailable"
		w.Header().Set("Tunn-Limit-Reason", s.reason)
		http.Error(w, "Usage ledger unavailable", 503)
		return false
	}
	w.Header().Set("Tunn-Request-ID", s.event.RequestId)
	setMeterHeaders(w, d)
	if !d.Allowed {
		s.reason = d.Reason
		http.Error(w, d.Reason, int(d.Status))
		return false
	}
	s.admitted = true
	if s.proxy.planMeter && s.accountID != "" && (d.RequestsRemaining < 0 || d.BytesRemaining < 0) {
		s.reason = "meter_unavailable"
		w.Header().Set("Tunn-Limit-Reason", s.reason)
		http.Error(w, "Usage authority must support account plan limits", 503)
		return false
	}
	return true
}
func (s *ingressMeter) charge(ctx context.Context, request bool, n int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, fmt.Errorf("ingress request finished")
	}
	if s.backend == nil {
		return n, nil
	}
	req, resp := s.requestBytes, s.responseBytes
	if request {
		req += int64(n)
	} else {
		resp += int64(n)
	}
	// Even caller cancellation must not erase already-read ingress bytes.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	d, err := s.backend.Charge(ctx, &pb.ChargeRequest{RequestId: s.event.RequestId, RequestBytes: req, ResponseBytes: resp})
	if err != nil {
		s.reason = "meter_unavailable"
		return 0, &meterUnavailableError{err}
	}
	allowed := d.ResponseBytes - s.responseBytes
	if request {
		allowed = d.RequestBytes - s.requestBytes
	}
	s.requestBytes = d.RequestBytes
	s.responseBytes = d.ResponseBytes
	if !d.Allowed {
		s.reason = d.Reason
		return int(allowed), &ingressLimitError{d}
	}
	return int(allowed), nil
}
func (s *ingressMeter) checkResponse(ctx context.Context, size int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backend == nil {
		return nil
	}
	d, err := s.backend.Charge(ctx, &pb.ChargeRequest{RequestId: s.event.RequestId, RequestBytes: s.requestBytes, ResponseBytes: s.responseBytes})
	if err != nil {
		s.reason = "meter_unavailable"
		return &meterUnavailableError{err}
	}
	if d.Allowed && d.BytesRemaining >= 0 && (d.BytesRemaining == 0 || size > d.BytesRemaining) {
		d.Allowed = false
		d.Status = 429
		d.Reason = d.ByteBudgetReason
		if d.Reason == "" { // compatibility with an older metering authority
			d.Reason = "byte_budget"
		}
		d.RetryAfter = 1
	}
	if !d.Allowed {
		s.reason = d.Reason
		return &ingressLimitError{d}
	}
	return nil
}

// Bound idle-stream revocation and ledger-outage exposure without allowing a
// cached quota decision. Every data chunk still needs an atomic reservation.
func (s *ingressMeter) watch(ctx context.Context, cancel context.CancelCauseFunc) {
	s.watchEvery(ctx, cancel, 5*time.Second)
}
func (s *ingressMeter) watchEvery(ctx context.Context, cancel context.CancelCauseFunc, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probe, stop := context.WithTimeout(ctx, 5*time.Second)
			err := s.checkResponse(probe, 0)
			stop()
			if err != nil {
				cancel(err)
				return
			}
		}
	}
}
func (s *ingressMeter) complete(ctx context.Context, w *meterResponseWriter) {
	if s.observing {
		s.observationOnce.Do(func() {
			s.proxy.operations.active.Add(-1)
			if !s.event.Forwarded && (w.status >= 400 || s.reason == "authentication_required") {
				s.proxy.operations.denied.Add(1)
			}
		})
	}
	if s.backend == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if !s.admitted {
		// Authentication/owner quota failures are first-class decisions too.
		// An unsuccessful meter RPC already fails closed and cannot fabricate an audit.
		if s.reason == "meter_unavailable" {
			if s.proxy != nil {
				s.proxy.operations.drops.Add(1)
			}
			return
		}
		s.event.Allowed = false
		s.event.Status = int32(w.status)
		s.event.Reason = s.reason
		if s.event.Reason == "" {
			s.event.Reason = "denied"
		}
		if _, err := s.backend.Admit(ctx, s.event); err != nil {
			if s.proxy != nil {
				s.proxy.operations.drops.Add(1)
			}
			common.LogError("failed to audit ingress rejection", "request_id", s.event.RequestId, "error", err)
		}
		return
	}
	if s.accountID != "" {
		s.proxy.RecordUsage(ctx, s.accountID, s.requestBytes+s.writtenBytes)
	}
	_, err := s.backend.Finish(ctx, &pb.Event{RequestId: s.event.RequestId, Status: int32(w.status), Reason: s.reason, Forwarded: s.event.Forwarded, ResponseBytes: s.writtenBytes})
	if err != nil {
		if s.proxy != nil {
			s.proxy.operations.drops.Add(1)
		}
		common.LogError("failed to finish ingress audit", "request_id", s.event.RequestId, "error", err)
	}
}

// WebSockets bypass the HTTP body writer after hijacking. Reserve each frame
// chunk before forwarding it, and reconcile actual egress at completion.
func chargeWebSocket(r *http.Request, request bool, data []byte) ([]byte, error) {
	if s := meterForRequest(r); s != nil {
		n, err := s.charge(r.Context(), request, len(data))
		// Never forward a partial WebSocket frame: that would corrupt framing.
		if err != nil {
			return nil, err
		}
		return data[:n], nil
	}
	return data, nil
}

func recordMeteredWrite(r *http.Request, n int) {
	if s := meterForRequest(r); s != nil {
		s.mu.Lock()
		s.writtenBytes += int64(n)
		s.mu.Unlock()
	}
}

type meterRequestBody struct {
	io.ReadCloser
	meter *ingressMeter
	ctx   context.Context
}

func (b *meterRequestBody) Read(buf []byte) (int, error) {
	n, err := b.ReadCloser.Read(buf)
	if n > 0 {
		allowed, chargeErr := b.meter.charge(b.ctx, true, n)
		if chargeErr != nil {
			return allowed, chargeErr
		}
	}
	return n, err
}

type meterResponseWriter struct {
	http.ResponseWriter
	meter              *ingressMeter
	ctx                context.Context
	status             int
	started, bodyMeter bool
}

func (w *meterResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *meterResponseWriter) WriteHeader(status int) {
	if w.started {
		return
	}
	w.status = status
	w.started = true
	w.ResponseWriter.WriteHeader(status)
}
func (w *meterResponseWriter) Write(body []byte) (int, error) {
	allowed := len(body)
	var chargeErr error
	if w.bodyMeter && len(body) > 0 {
		allowed, chargeErr = w.meter.charge(w.ctx, false, len(body))
		var limit *ingressLimitError
		if errors.As(chargeErr, &limit) {
			w.Header().Set("Tunn-Limit-Reason", limit.decision.Reason)
		}
		if chargeErr != nil && allowed == 0 {
			return 0, chargeErr
		}
	}
	if !w.started {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(body[:allowed])
	if w.bodyMeter {
		w.meter.mu.Lock()
		w.meter.writtenBytes += int64(n)
		w.meter.mu.Unlock()
	}
	if err != nil {
		return n, err
	}
	return n, chargeErr
}
func (w *meterResponseWriter) Flush() {
	if !w.started {
		w.WriteHeader(200)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Explicit grant attempts take precedence over cookies, including on public
// endpoints. Revoked/expired credentials must never fall back to anonymous use.
func grantBearer(r *http.Request) (string, string) {
	for _, name := range []string{"Tunn-Authorization", "Authorization"} {
		fields := strings.Fields(r.Header.Get(name))
		if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") && strings.HasPrefix(fields[1], "tunn_gr_") {
			return fields[1], name
		}
	}
	return "", ""
}
func strippedAuth(r *http.Request, header string) *http.Request {
	clone := r.Clone(r.Context())
	clone.Header = r.Header.Clone()
	consumed := r.Header.Get(header)
	clone.Header.Del(header)
	// Authorization can also carry application credentials. Remove the
	// consumed value while retaining unrelated values for boundary filtering.
	if strings.EqualFold(header, "Authorization") {
		for _, value := range r.Header.Values(header) {
			if value != consumed {
				clone.Header.Add(header, value)
			}
		}
	}
	return clone
}
func meterForRequest(r *http.Request) *ingressMeter {
	s, _ := r.Context().Value(meterContextKey{}).(*ingressMeter)
	return s
}
func checkMeteredResponse(r *http.Request, size int64) error {
	if s := meterForRequest(r); s != nil {
		return s.checkResponse(r.Context(), size)
	}
	return nil
}

// Management API accepts owner bearer credentials only (no cookie-based writes),
// and never treats an endpoint/grant credential as an owner credential.
func (p *ProxyServer) handleMeteringAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/endpoints/"), "/")
	if r.URL.Path == "/api/usage" {
		parts = []string{r.URL.Query().Get("tunnel"), "usage"}
	} else if r.URL.Path == "/api/grants" && r.Method == http.MethodGet {
		parts = []string{r.URL.Query().Get("tunnel"), "grants"}
	}
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "" && !isValidDNSLabel(parts[0]) || parts[0] == "" && r.URL.Path != "/api/usage" && r.URL.Path != "/api/grants" {
		http.NotFound(w, r)
		return
	}
	endpoint := parts[0]
	if p.meter == nil {
		http.Error(w, "Usage ledger unavailable", 503)
		return
	}
	email, _, capability, ok := p.getAuthFromTunnelBearer(r, &TunnelConnection{})
	if !ok || capability {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tunn-owner"`)
		http.Error(w, "Owner authentication required", 401)
		return
	}
	if p.storage == nil || !p.storage.Available() {
		http.Error(w, "Account service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	account, err := p.storage.GetAccountByEmail(r.Context(), common.NormalizeEmail(email))
	if err != nil {
		http.Error(w, "Account service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if account == nil || account.ID == "" {
		http.Error(w, "Owner account could not be verified", http.StatusForbidden)
		return
	}
	owner := account.ID
	if r.Method == http.MethodPost && account.OperationalState != "active" {
		http.Error(w, "account_suspended", 403)
		return
	}
	switch {
	case parts[1] == "usage" && len(parts) == 2 && r.Method == http.MethodGet:
		month := r.URL.Query().Get("month")
		export := &pb.ExportRequest{Owner: owner, Endpoint: endpoint, Month: month}
		if since, exists := r.URL.Query()["since"]; exists {
			duration, err := time.ParseDuration(since[0])
			now := time.Now().UTC()
			if err != nil || duration < time.Millisecond || now.Add(-duration).UnixMilli() <= 0 || r.URL.Query().Has("month") {
				http.Error(w, "since must be a positive duration and cannot be combined with month", 400)
				return
			}
			// Export's upper bound is exclusive; include events recorded during
			// this millisecond, including a request that just completed.
			export.Since, export.Until = now.Add(-duration).UnixMilli(), now.UnixMilli()+1
		} else {
			if month == "" {
				month = time.Now().UTC().Format("2006-01")
			}
			if parsed, err := time.Parse("2006-01", month); err != nil || parsed.Format("2006-01") != month {
				http.Error(w, "month must be YYYY-MM", 400)
				return
			}
			export.Month = month
		}
		out, err := p.meter.Export(r.Context(), export)
		if err != nil {
			p.operations.drops.Add(1)
			http.Error(w, "Usage ledger unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(out); err != nil {
			p.operations.drops.Add(1)
		}
	case parts[1] == "grants" && len(parts) == 2 && r.Method == http.MethodGet:
		out, err := p.meter.ListGrants(r.Context(), &pb.ListGrantsRequest{Owner: owner, Endpoint: endpoint})
		if err != nil {
			http.Error(w, "Usage ledger unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	case parts[1] == "grants" && len(parts) == 2 && r.Method == http.MethodPost:
		tunnel, exists := p.tunnelServer.GetTunnel(endpoint)
		if !exists {
			// The publisher node proves live endpoint ownership before creation. Route
			// once using ordinary cluster discovery, without creating an ingress event.
			p.cacheMu.RLock()
			addr, cached := p.tunnelCache[endpoint]
			p.cacheMu.RUnlock()
			if !cached {
				for _, client := range p.nodeClients {
					probeCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
					probe, err := client.FindTunnel(probeCtx, &internalv1.FindTunnelRequest{TunnelId: endpoint})
					cancel()
					if err == nil && probe.Found {
						addr = probe.NodeAddress
						break
					}
				}
			}
			if addr != "" {
				p.proxyToNode(w, r, addr, endpoint)
				return
			}
			http.Error(w, "Endpoint offline", 503)
			return
		}
		tunnelAccount, err := p.currentTunnelAccount(r.Context(), tunnel)
		if err != nil {
			http.Error(w, "Account service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if tunnelAccount == nil || tunnelAccount.ID != owner {
			http.Error(w, "Only the endpoint owner can create grants", 403)
			return
		}
		if tunnel.EndpointProtocol == "tcp" {
			http.Error(w, "Metered grants currently support HTTP endpoints", 400)
			return
		}
		var g pb.Grant
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&g); err != nil {
			http.Error(w, "Invalid grant", 400)
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			http.Error(w, "Invalid grant", 400)
			return
		}
		g.Owner = owner
		g.Endpoint = endpoint
		g.Consumer = common.NormalizeEmail(g.Consumer)
		out, err := p.meter.CreateGrant(r.Context(), &g)
		if err != nil {
			http.Error(w, "Invalid grant or ledger unavailable", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(out)
	case parts[1] == "grants" && len(parts) == 3 && r.Method == http.MethodDelete:
		_, err := p.meter.RevokeGrant(r.Context(), &pb.Grant{Owner: owner, Endpoint: endpoint, Id: parts[2]})
		if err != nil {
			http.Error(w, "Grant not found or ledger unavailable", 404)
			return
		}
		w.WriteHeader(204)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "Unsupported management operation", 405)
	}
}

func writeIngressError(w http.ResponseWriter, err error) {
	var unavailable *meterUnavailableError
	if errors.As(err, &unavailable) {
		w.Header().Set("Tunn-Limit-Reason", "meter_unavailable")
		http.Error(w, "Usage ledger unavailable", 503)
		return
	}
	var limit *ingressLimitError
	if errors.As(err, &limit) {
		setMeterHeaders(w, limit.decision)
		http.Error(w, limit.decision.Reason, int(limit.decision.Status))
		return
	}
	http.Error(w, "Failed to proxy request", 502)
}
