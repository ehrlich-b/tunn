package host

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

// Only the explicit browser target enables this fixture; ordinary Go tests need
// neither Node nor Chromium. All fixture endpoints exist only in this test.
func TestPayJourneyBrowser(t *testing.T) {
	if os.Getenv("TUNN_PAY_JOURNEY") != "1" {
		t.Skip("run make test-pay-journey")
	}
	evidence := os.Getenv("TUNN_PAY_JOURNEY_EVIDENCE")
	if evidence == "" {
		t.Fatal("TUNN_PAY_JOURNEY_EVIDENCE is required")
	}
	for _, period := range []string{"monthly", "yearly"} {
		for _, width := range []int{390, 1440} {
			t.Run(fmt.Sprintf("%s/%d", period, width), func(t *testing.T) {
				payJourneyBrowser(t, evidence, period, width)
			})
		}
	}
}

func payJourneyBrowser(t *testing.T, evidence, period string, width int) {
	p, db := stripeCorrectnessFixture(t)
	local := p.storage.(*storage.LocalStorage)
	p.Domain = p.config.Domain
	p.config.GitHubClientID = ""
	p.config.BillingEnabled = true
	p.config.StripeWebhookSecret = "whsec_first_fixture"
	p.config.StripeCheckoutURLMonthly = "https://buy.stripe.com/monthly_fixture"
	p.config.StripeCheckoutURLYearly = "https://buy.stripe.com/yearly_fixture"
	mail := new(accountsMailCapture)
	p.emailSender = mail
	provider := newFirstCustomerStripeFixture("price_" + period)
	p.storage = autoStripeStorage{local, store.NewStripeAutomation("sk_test_fixture", []string{"price_" + period}, provider.transport(t))}
	publishers := newPayJourneyPublishers(t, p, db)
	handler := p.createHandler()
	var server *httptest.Server
	var webhookStatus int
	var webhookResult store.BillingResult
	var checkoutAccount string
	var beforePlan string
	fixture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both permitted browser hostnames resolve to this loopback fixture.
		switch r.URL.Path {
		case "/_fixture/limit":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(publishers.facts)
		case "/_fixture/mail":
			if mail.calls != 1 || mail.link == "" {
				http.Error(w, "missing fixture delivery", 500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"to": mail.to, "link": mail.link})
		case "/monthly_fixture", "/yearly_fixture":
			a, err := local.GetAccountByEmail(r.Context(), r.URL.Query().Get("prefilled_email"))
			if err != nil || a == nil || r.URL.Path != "/"+period+"_fixture" || r.Host != "buy.stripe.com" {
				http.Error(w, "unknown fixture checkout buyer", 500)
				return
			}
			reference := r.URL.Query().Get("client_reference_id")
			var account, destination string
			if err := db.QueryRow(`SELECT i.account_id,d.destination FROM ops_checkout_intents i JOIN ops_checkout_destinations d USING(reference) WHERE i.reference=?`, reference).Scan(&account, &destination); err != nil || account != a.ID || !strings.Contains(destination, period+"_fixture") || reference == a.ID || r.URL.Query().Get("prefilled_email") != a.PrimaryEmail {
				http.Error(w, "checkout lost its durable owner or period", 500)
				return
			}
			checkoutAccount, beforePlan = a.ID, a.Plan
			if a.Plan != "free" {
				http.Error(w, "buyer was already Pro", 500)
				return
			}
			if err := publishers.beforePayment(a); err != nil {
				http.Error(w, "before-payment limit: "+err.Error(), 500)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tmpl := template.Must(template.New("checkout").Parse(`<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Fixture checkout</title></head><body><h1>Fixture checkout</h1><p>Pro {{.Period}}</p><p>{{.Price}}</p><p>{{.Email}}</p><form method="post" action="https://{{.Authority}}/_fixture/pay"><input type="hidden" name="reference" value="{{.Reference}}"><button>Pay fixture</button></form></body></html>`))
			price := "$5/month"
			if period == "yearly" {
				price = "$48/year"
			}
			_ = tmpl.Execute(w, map[string]string{"Period": period, "Price": price, "Email": a.PrimaryEmail, "Reference": reference, "Authority": p.config.PublicAddr})
		case "/_fixture/pay":
			if r.Method != http.MethodPost || r.Header.Get("Origin") != "https://buy.stripe.com" {
				http.Error(w, "invalid fixture payment origin", 403)
				return
			}
			a, err := local.GetAccount(r.Context(), checkoutAccount)
			if err != nil || a == nil {
				http.Error(w, "missing fixture buyer", 500)
				return
			}
			reference := r.PostFormValue("reference")
			var account, created string
			if err := db.QueryRow(`SELECT account_id,created_at FROM ops_checkout_intents WHERE reference=?`, reference).Scan(&account, &created); err != nil || account != a.ID || a.ID != checkoutAccount {
				http.Error(w, "unknown fixture intent", 500)
				return
			}
			issued, err := time.Parse(time.RFC3339Nano, created)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			duration := int64(30 * 24 * 3600)
			if period == "yearly" {
				duration = 365 * 24 * 3600
			}
			provider.start, provider.end = issued.Unix()-10, issued.Unix()+duration
			body := fmt.Sprintf(`{"id":"evt_checkout","created":%d,"type":"checkout.session.completed","data":{"object":{"id":"cs_first","customer":"cus_first","subscription":"sub_first","mode":"subscription","payment_status":"paid","client_reference_id":%q}}}`, issued.Unix(), reference)
			req, err := http.NewRequest(http.MethodPost, server.URL+"/webhooks/stripe", strings.NewReader(body))
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			req.Host = p.config.PublicAddr
			req.Header.Set("Content-Type", "application/json")
			signature := signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix())
			req.Header.Set("Stripe-Signature", signature)
			signedWebhookSent := time.Now()
			resp, err := server.Client().Do(req)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			defer resp.Body.Close()
			webhookStatus = resp.StatusCode
			raw, err := io.ReadAll(resp.Body)
			if err != nil || json.Unmarshal(raw, &webhookResult) != nil || webhookStatus != 200 || webhookResult.State != "reconciled" || webhookResult.AccountID != a.ID {
				http.Error(w, "signed webhook failed: "+string(raw), 500)
				return
			}
			if err := publishers.afterPayment(signedWebhookSent); err != nil {
				http.Error(w, "after-payment limit: "+err.Error(), 500)
				return
			}
			run := fmt.Sprintf("%s-%d", period, width)
			writePayJSON(t, filepath.Join(evidence, run+"-webhook.json"), map[string]any{"body": body, "signature": signature, "http_status": webhookStatus, "result": webhookResult, "limit": publishers.facts})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Fixture payment received</title></head><body><h1>Fixture payment received</h1><p>Signed webhook: reconciled</p><a href="/account?billing=return">Return to account</a></body></html>`)
		default:
			handler.ServeHTTP(w, r)
		}
	})
	server = httptest.NewUnstartedServer(fixture)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p.config.PublicAddr = p.config.Domain + ":" + port
	server.StartTLS()
	defer server.Close()
	run := fmt.Sprintf("%s-%d", period, width)
	input := filepath.Join(evidence, run+"-input.json")
	writePayJSON(t, input, map[string]any{"apex": "https://" + p.config.PublicAddr, "period": period, "width": width, "email": "stranger+" + run + "@example.com", "output": evidence})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../scripts/integration-tests/pay-journey-browser.cjs", input)
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("browser journey: %v", err)
	}
	a, err := local.GetAccount(context.Background(), checkoutAccount)
	if err != nil || a == nil || a.Plan != "pro" || beforePlan != "free" || provider.reads != 1 || webhookStatus != 200 {
		t.Fatal("payment did not commit Pro", a, err, provider.reads, webhookStatus)
	}
	var mappings, audits int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM ops_billing_mappings WHERE account_id=?),(SELECT count(*) FROM ops_billing_events WHERE actor='system:stripe')`, a.ID).Scan(&mappings, &audits); err != nil || mappings != 1 || audits != 1 {
		t.Fatal("missing durable billing ownership", mappings, audits, err)
	}
	writePayJSON(t, filepath.Join(evidence, run+"-authority.json"), map[string]any{"before_plan": beforePlan, "after_plan": a.Plan, "provider_reads": provider.reads, "provider_transport": "firstCustomerStripeFixture: in-memory, no socket", "mappings": mappings, "automatic_audits": audits, "webhook_status": webhookStatus, "webhook_state": webhookResult.State, "period_seconds": provider.end - provider.start - 10, "width": width, "limit": publishers.facts})
}

func writePayJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
