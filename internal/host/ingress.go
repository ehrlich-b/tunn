package host

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

const ingressStorageTimeout = 2 * time.Second
const maxPendingIngress = 1024

type ingressMeterKey struct{}
type ingressMeter struct {
	ledger        bool // owner bandwidth commits with the event, exactly once
	requestBytes  atomic.Int64
	responseBytes atomic.Int64
	forwarded     atomic.Bool
}

func meterFor(r *http.Request) *ingressMeter {
	m, _ := r.Context().Value(ingressMeterKey{}).(*ingressMeter)
	return m
}
func markForwarded(r *http.Request) {
	if m := meterFor(r); m != nil {
		m.forwarded.Store(true)
	}
}
func meterRequest(r *http.Request, n int) {
	if m := meterFor(r); m != nil {
		m.requestBytes.Add(int64(n))
	}
}
func meterResponse(r *http.Request, n int) {
	if m := meterFor(r); m != nil {
		m.responseBytes.Add(int64(n))
	}
}

// statusWriter preserves ResponseController capabilities and streaming flushes.
// Response bytes are metered in the data adapters, excluding ingress error pages.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *statusWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
func (w *statusWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Completed events use a detached, bounded context so caller cancellation cannot
// discard accounting. Retries reuse the ID; only the hosting node produces it.
func (p *ProxyServer) recordIngress(e store.IngressEvent) {
	ledger, ok := p.storage.(storage.IngressStorage)
	if !ok || e.AccountID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), ingressStorageTimeout)
	err := ledger.RecordIngress(ctx, e)
	cancel()
	if err == nil {
		return
	}
	p.ingressMu.Lock()
	if p.pendingIngress == nil {
		p.pendingIngress = make(map[string]store.IngressEvent)
	}
	if len(p.pendingIngress) < maxPendingIngress {
		p.pendingIngress[e.RequestID] = e
	} else {
		common.LogError("ingress accounting queue full; event lost", "request_id", e.RequestID)
	}
	p.ingressMu.Unlock()
	common.LogError("ingress accounting delayed", "request_id", e.RequestID, "error", err)
}
func (p *ProxyServer) flushIngress(ctx context.Context) {
	ledger, ok := p.storage.(storage.IngressStorage)
	if !ok {
		return
	}
	p.ingressMu.Lock()
	events := make([]store.IngressEvent, 0, len(p.pendingIngress))
	for _, e := range p.pendingIngress {
		events = append(events, e)
	}
	p.ingressMu.Unlock()
	for _, e := range events {
		if ctx.Err() != nil {
			return
		}
		attempt, cancel := context.WithTimeout(ctx, ingressStorageTimeout)
		err := ledger.RecordIngress(attempt, e)
		cancel()
		if err != nil {
			return
		}
		p.ingressMu.Lock()
		delete(p.pendingIngress, e.RequestID)
		p.ingressMu.Unlock()
	}
}
func (p *ProxyServer) ingressFlushLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.flushIngress(ctx)
		}
	}
}

// handleIngressExport accepts account credentials only. Endpoint capabilities
// authorize forwarding, never owner data. The account ID is always server-derived.
func (p *ProxyServer) handleIngressExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie, Authorization, Tunn-Authorization")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	email, ok := p.getAuthFromCookie(r)
	if !ok {
		email, _, _, ok = p.getAuthFromTunnelBearer(r, &TunnelConnection{})
	}
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tunn"`)
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	if p.storage == nil || !p.storage.Available() {
		http.Error(w, "Usage storage unavailable", http.StatusServiceUnavailable)
		return
	}
	account, err := p.storage.GetAccountByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "Usage storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if account == nil {
		http.Error(w, "Account not found", http.StatusForbidden)
		return
	}
	q := store.IngressQuery{AccountID: account.ID, Month: r.URL.Query().Get("month"), EndpointID: r.URL.Query().Get("endpoint"), Limit: 100}
	if q.Month == "" {
		q.Month = time.Now().UTC().Format("2006-01")
	}
	if after := r.URL.Query().Get("after"); after != "" {
		q.After, err = strconv.ParseInt(after, 10, 64)
		if err != nil {
			http.Error(w, "Invalid cursor", 400)
			return
		}
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		q.Limit, err = strconv.Atoi(limit)
		if err != nil {
			http.Error(w, "Invalid limit", 400)
			return
		}
	}
	switch r.URL.Query().Get("view") {
	case "", "events":
	case "counters":
		q.Counters = true
	default:
		http.Error(w, "Invalid view", 400)
		return
	}
	if q.Validate() != nil {
		http.Error(w, "Invalid usage query", http.StatusBadRequest)
		return
	}
	ledger, ok := p.storage.(storage.IngressStorage)
	if !ok {
		http.Error(w, "Usage storage unavailable", http.StatusServiceUnavailable)
		return
	}
	out, err := ledger.ExportIngress(r.Context(), q)
	if err != nil {
		http.Error(w, "Usage storage unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
