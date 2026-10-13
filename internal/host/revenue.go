package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

type revenuePageData struct {
	MonthlyUSD, YearlyUSD             int
	FreeTunnels, ProTunnels           int
	FreeRequests, ProRequests         int64
	FreeBytes, ProBytes               string
	Reservations                      int
	MonthlyAvailable, YearlyAvailable bool
}

// Restrict configured destinations to Stripe origins. Missing/malformed config
// renders unavailable rather than a no-op or open redirect. No API writes occur.
func stripeURL(raw, host string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	return u, err == nil && u.Scheme == "https" && u.Host == host && u.User == nil && u.Fragment == "" && strings.HasPrefix(u.Path, "/") && len(u.Path) > 1
}

func (p *ProxyServer) revenueData() revenuePageData {
	monthly, yearly := 6, 60
	if p.config.ProMonthlyUSD > 0 {
		monthly = p.config.ProMonthlyUSD
	}
	if p.config.ProYearlyUSD > 0 {
		yearly = p.config.ProYearlyUSD
	}
	_, monthOK := stripeURL(p.config.StripeCheckoutURLMonthly, "buy.stripe.com")
	_, yearOK := stripeURL(p.config.StripeCheckoutURLYearly, "buy.stripe.com")
	freeRequests, proRequests := metering.FreeMonthlyRequests, metering.ProMonthlyRequests
	freeBytes, proBytes := FreeQuotaBytes, ProQuotaBytes
	if p.config.OwnerMonthlyRequests > 0 {
		freeRequests = min(freeRequests, p.config.OwnerMonthlyRequests)
		proRequests = min(proRequests, p.config.OwnerMonthlyRequests)
	}
	if p.config.OwnerMonthlyBytes > 0 {
		freeBytes = min(freeBytes, p.config.OwnerMonthlyBytes)
		proBytes = min(proBytes, p.config.OwnerMonthlyBytes)
	}
	return revenuePageData{MonthlyUSD: monthly, YearlyUSD: yearly, FreeTunnels: storage.FreeTunnelLimit, ProTunnels: storage.ProTunnelLimit, FreeRequests: freeRequests, ProRequests: proRequests, FreeBytes: formatBytes(freeBytes), ProBytes: formatBytes(proBytes), Reservations: store.MaxReservedSubdomains, MonthlyAvailable: p.config.BillingEnabled && p.config.StripeWebhookSecret != "" && monthOK, YearlyAvailable: p.config.BillingEnabled && p.config.StripeWebhookSecret != "" && yearOK}
}

func (p *ProxyServer) renderRevenuePage(w http.ResponseWriter, content string) {
	tmpl, err := template.New("revenue").Parse(content)
	if err != nil {
		http.Error(w, "Page unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err = tmpl.Execute(w, p.revenueData()); err != nil {
		http.Error(w, "Page unavailable", http.StatusInternalServerError)
	}
}

func (p *ProxyServer) handlePricing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	writePageStart(w, "tunn - Pricing")
	p.renderRevenuePage(w, pricingHTML)
	writePageEnd(w)
}

func (p *ProxyServer) handleComparison(w http.ResponseWriter, r *http.Request) {
	p.serveDistributionPage(w, r)
}

func (p *ProxyServer) handleDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if r.URL.Path != "/docs" && r.URL.Path != "/docs/" && r.URL.Path != "/docs/mcp-to-claude" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Path == "/docs/mcp-to-claude" {
		if r.Method != http.MethodHead {
			_, _ = fmt.Fprint(w, mcpToClaudeHTML)
		}
		return
	} else {
		writePageStart(w, "tunn - Quickstart")
		_, _ = fmt.Fprint(w, docsHTML)
	}
	writePageEnd(w)
}

func (p *ProxyServer) revenueAccount(w http.ResponseWriter, r *http.Request) *storage.Account {
	w.Header().Set("Cache-Control", "no-store")
	email, ok := p.getAuthFromCookie(r)
	if !ok {
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return nil
	}
	if p.storage == nil || !p.storage.Available() {
		http.Error(w, "Account service unavailable. Please retry.", 503)
		return nil
	}
	a, err := p.storage.GetAccountByEmail(r.Context(), email)
	if err != nil || a == nil {
		http.Error(w, "Account service unavailable. Please retry.", 503)
		return nil
	}
	return a
}

// handleUpgrade redirects the authenticated owner to a configured Payment Link.
// Its editable reference/email are reconciliation hints, never entitlement proof.
func (p *ProxyServer) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	a := p.revenueAccount(w, r)
	if a == nil {
		return
	}
	if a.OperationalState == "suspended" {
		http.Error(w, "Account suspended", 403)
		return
	}
	if a.Plan == "pro" {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "monthly"
	}
	d := p.revenueData()
	raw := p.config.StripeCheckoutURLMonthly
	available := d.MonthlyAvailable
	if period == "yearly" {
		raw = p.config.StripeCheckoutURLYearly
		available = d.YearlyAvailable
	} else if period != "monthly" {
		http.Error(w, "Choose monthly or yearly billing", 400)
		return
	}
	if !available {
		w.WriteHeader(http.StatusServiceUnavailable)
		writePageStart(w, "tunn - Checkout unavailable")
		_, _ = fmt.Fprint(w, `<h1 class="page-title">Checkout is not available yet</h1><p>Free tunnels still work. Please check back after billing opens.</p><a href="/pricing">See plans</a>`)
		writePageEnd(w)
		return
	}
	checkout, ok := p.storage.(storage.DurableBillingCheckout)
	if !ok {
		http.Error(w, "Billing authority unavailable. Please retry.", 503)
		return
	}
	reference, destination, err := checkout.PrepareBillingCheckout(r.Context(), a.ID, raw)
	if err != nil {
		if errors.Is(err, store.ErrCheckoutBlocked) {
			http.Error(w, "A purchase or previous subscription needs review. Do not pay again. Contact support@tunn.to.", 409)
		} else if errors.Is(err, store.ErrSuspended) {
			http.Error(w, "Account suspended", 403)
		} else {
			http.Error(w, "Billing authority unavailable. Please retry.", 503)
		}
		return
	}
	u, valid := stripeURL(destination, "buy.stripe.com")
	if !valid {
		http.Error(w, "Saved checkout destination unavailable. Contact support@tunn.to.", 503)
		return
	}
	q := u.Query()
	q.Set("prefilled_email", a.PrimaryEmail)
	q.Set("client_reference_id", reference)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// handleBillingStatus reads derived committed entitlement. Return parameters,
// checkout receipts and client-supplied session IDs grant nothing.
func (p *ProxyServer) handleBillingStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	a := p.revenueAccount(w, r)
	if a == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	state := "pending"
	if a.Plan == "pro" {
		state = "active"
	}
	if a.OperationalState == "suspended" {
		state = "suspended"
	}
	_ = json.NewEncoder(w).Encode(struct {
		Plan   string `json:"plan"`
		State  string `json:"state"`
		Notice string `json:"notice,omitempty"`
	}{a.Plan, state, a.BillingNotice})
}
