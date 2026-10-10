package host

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ehrlich-b/tunn/internal/store"
)

func (p *ProxyServer) handleReportIntake(w http.ResponseWriter, r *http.Request) {
	if extractTunnelID(r.Host, p.Domain) != "" {
		p.handleWebProxy(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	email, _, capability, ok := p.getAuthFromTunnelBearer(r, &TunnelConnection{})
	if !ok || capability {
		http.Error(w, "Account authentication required", 401)
		return
	}
	if p.storage == nil || !p.storage.Available() {
		http.Error(w, "Intake unavailable", 503)
		return
	}
	account, err := p.storage.GetAccountByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "Account service unavailable", 503)
		return
	}
	if account == nil {
		http.Error(w, "Account required", 403)
		return
	}
	var metadata struct {
		Category string `json:"category"`
		Endpoint string `json:"endpoint"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if d.Decode(&metadata) != nil {
		http.Error(w, "Invalid intake metadata", 400)
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		http.Error(w, "Expected one report", 400)
		return
	}
	intake, ok := p.storage.(interface {
		IntakeReport(context.Context, string, string, string) (*store.IncidentReport, error)
	})
	if !ok {
		http.Error(w, "Intake unavailable", 503)
		return
	}
	report, err := intake.IntakeReport(r.Context(), account.ID, metadata.Category, metadata.Endpoint)
	if err != nil {
		state, code := "invalid_metadata", 400
		if errors.Is(err, store.ErrReportRateLimited) {
			state, code = "rate_limited", 429
		}
		if errors.Is(err, store.ErrReportCapacity) {
			state, code = "capacity", 503
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"state": state})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(report)
}
