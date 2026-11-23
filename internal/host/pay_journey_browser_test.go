package host

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
				payJourneyBrowser(t, evidence, period, width, "")
			})
		}
	}
	for _, scenario := range []string{"unsigned-webhook", "other-account-webhook", "replayed-checkout"} {
		for _, width := range []int{390, 1440} {
			t.Run(fmt.Sprintf("%s/%d", scenario, width), func(t *testing.T) {
				payJourneyBrowser(t, evidence, "monthly", width, scenario)
			})
		}
	}
}

func payJourneyBrowser(t *testing.T, evidence, period string, width int, scenario string) {
	runStart := time.Now().Unix()
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
	handler := p.createHandler()
	run := fmt.Sprintf("%s-%d", period, width)
	if scenario != "" {
		run = fmt.Sprintf("%s-%d", scenario, width)
	}
	var donorID string
	var control map[string]any
	var server *httptest.Server
	var webhookStatus int
	var webhookResult store.BillingResult
	var checkoutAccount string
	var beforePlan string
	var positiveAuthority map[string]any
	var captures []map[string]any
	var captureMu sync.Mutex
	// This wrapper observes the actual POST before the production handler runs.
	// Neither the signature timestamp nor event.created supplies this clock.
	capturePost := func(w http.ResponseWriter, r *http.Request) {
		received := time.Now().Unix()
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		session := ""
		if email, ok := p.getAuthFromCookie(r); ok {
			account, err := local.GetAccountByEmail(r.Context(), email)
			if err != nil || account == nil {
				t.Fatal("POST session account", err)
			}
			session = account.ID
		}
		captureMu.Lock()
		defer captureMu.Unlock()
		id := len(captures) + 1
		capture := map[string]any{"capture_id": id, "run": run, "received_unix": received,
			"method": r.Method, "path": r.URL.Path, "session_account": session,
			"body": string(raw), "signature": r.Header.Get("Stripe-Signature"),
			"body_sha256": fmt.Sprintf("%x", sha256.Sum256(raw))}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		capture["http_status"], capture["response_body"] = rec.Code, rec.Body.String()
		capture["response_sha256"] = fmt.Sprintf("%x", sha256.Sum256(rec.Body.Bytes()))
		captures = append(captures, capture)
		for key, values := range rec.Header() {
			w.Header()[key] = values
		}
		w.Header().Set("X-Fixture-Post", strconv.Itoa(id))
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}
	bindPost := func(receipt map[string]any, response *http.Response) {
		id, err := strconv.Atoi(response.Header.Get("X-Fixture-Post"))
		captureMu.Lock()
		defer captureMu.Unlock()
		if err != nil || id < 1 || id > len(captures) {
			t.Fatal("missing actual POST capture")
		}
		receipt["capture_id"], receipt["received_unix"] = id, captures[id-1]["received_unix"]
	}
	fixture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both permitted browser hostnames resolve to this loopback fixture.
		switch r.URL.Path {
		case "/webhooks/stripe":
			capturePost(w, r)
		case "/_fixture/donor-session":
			if scenario != "replayed-checkout" || donorID == "" {
				http.Error(w, "no donor", 404)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "tunn_auth", Value: relayJWT(t, p, "donor@example.invalid"), Domain: "." + p.config.Domain, Path: "/", Secure: true, HttpOnly: true})
			http.Redirect(w, r, "/account?billing=return", http.StatusSeeOther)
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
			if scenario != "" {
				targetReference := reference
				var receipts []map[string]any
				send := func(body, signature string) map[string]any {
					req, err := http.NewRequest(http.MethodPost, server.URL+"/webhooks/stripe", strings.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					req.Host = p.config.PublicAddr
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Stripe-Signature", signature)
					// A target's authenticated session cannot transfer ownership of a payment.
					req.AddCookie(&http.Cookie{Name: "tunn_auth", Value: relayJWT(t, p, a.PrimaryEmail)})
					resp, err := server.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					raw, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					receipt := map[string]any{"body": body, "signature": signature, "http_status": resp.StatusCode, "response_body": string(raw), "method": "POST", "path": "/webhooks/stripe", "session_account": a.ID, "body_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(body))), "response_sha256": fmt.Sprintf("%x", sha256.Sum256(raw))}
					bindPost(receipt, resp)
					receipts = append(receipts, receipt)
					return receipt
				}
				event := func(id, ref string) string {
					return fmt.Sprintf(`{"id":%q,"created":%d,"type":"checkout.session.completed","data":{"object":{"id":"cs_first","customer":"cus_first","subscription":"sub_first","mode":"subscription","payment_status":"paid","client_reference_id":%q,"metadata":{"account_id":%q}}}}`, id, issued.Unix(), ref, a.ID)
				}
				if scenario != "unsigned-webhook" {
					donor, err := local.FindOrCreateByEmails(r.Context(), []string{"donor@example.invalid"}, "fixture")
					if err != nil || donor == nil || donor.Plan != "free" {
						t.Fatal("donor must start Free", err)
					}
					donorID = donor.ID
					req := httptest.NewRequest("GET", "https://"+p.config.PublicAddr+"/upgrade?period="+period, nil)
					req.AddCookie(&http.Cookie{Name: "tunn_auth", Value: relayJWT(t, p, donor.PrimaryEmail)})
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					destination, err := url.Parse(rec.Header().Get("Location"))
					if err != nil || rec.Code != 303 {
						t.Fatal("donor checkout", rec.Code, err)
					}
					reference = destination.Query().Get("client_reference_id")
					if reference == "" || reference == targetReference {
						t.Fatal("donor intent not isolated")
					}
					if err := db.QueryRow(`SELECT account_id,created_at FROM ops_checkout_intents WHERE reference=?`, reference).Scan(&account, &created); err != nil {
						t.Fatal(err)
					}
					if account != donorID {
						t.Fatal("donor intent owner mismatch")
					}
					issued, err = time.Parse(time.RFC3339Nano, created)
					if err != nil {
						t.Fatal(err)
					}
					provider.start, provider.end = issued.Unix()-10, issued.Unix()+duration
				}
				body := event("evt_control", reference)
				signature := signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix())
				if scenario == "unsigned-webhook" {
					signature = ""
				}
				first := send(body, signature)
				expectedStatus := 200
				if scenario == "unsigned-webhook" {
					expectedStatus = 400
				}
				if first["http_status"] != expectedStatus {
					t.Fatal("control response", first)
				}
				if scenario == "replayed-checkout" {
					// Exact replay is harmless for the legitimately paid donor. Then a signed
					// event-ID replay with a substituted target intent must be rejected.
					duplicate := send(body, signature)
					var result store.BillingResult
					if duplicate["http_status"] != 200 || json.Unmarshal([]byte(duplicate["response_body"].(string)), &result) != nil || !result.Duplicate || result.AccountID != donorID {
						t.Fatal("idempotent replay", duplicate)
					}
					altered := event("evt_control", targetReference)
					rejected := send(altered, signedStripeFixture(altered, p.config.StripeWebhookSecret, time.Now().Unix()))
					if rejected["http_status"] != 503 {
						t.Fatal("conflicting replay was accepted", rejected)
					}
					// A fresh event ID must reach checkout ownership independently of
					// event deduplication, even with the target's replacement intent.
					fresh := event("evt_control_replay", targetReference)
					replayed := send(fresh, signedStripeFixture(fresh, p.config.StripeWebhookSecret, time.Now().Unix()))
					if replayed["http_status"] != 200 || json.Unmarshal([]byte(replayed["response_body"].(string)), &result) != nil || result.Duplicate || result.State != "reconciled" || result.EventID != "evt_control_replay" || result.AccountID != donorID {
						t.Fatal("fresh checkout replay lost paid owner", replayed)
					}
				}
				current, err := local.GetAccount(r.Context(), a.ID)
				if err != nil || current.Plan != "free" {
					t.Fatal("negative signal granted target Pro", current, err)
				}
				donorPlan := ""
				if donorID != "" {
					donor, err := local.GetAccount(r.Context(), donorID)
					if err != nil || donor.Plan != "pro" {
						t.Fatal("legitimate owner lost Pro", donor, err)
					}
					donorPlan = donor.Plan
				}
				control = map[string]any{"name": scenario, "target_account": a.ID, "target_email": a.PrimaryEmail, "target_reference": targetReference, "payment_reference": reference, "donor_account": donorID, "donor_plan": donorPlan, "before_plan": beforePlan, "expected_plan": "free", "after_plan": current.Plan, "receipts": receipts}
				// Retain the database intent time independently of the signed event so
				// the report verifier can check completion eligibility, not just HMACs.
				control["payment_intent_created_unix"] = issued.Unix()
				if scenario == "replayed-checkout" {
					var paymentAccount, paymentReference string
					if err := db.QueryRow(`SELECT account_id,reference FROM ops_checkout_payments WHERE provider='stripe' AND subscription_id='sub_first' AND session_id='cs_first'`).Scan(&paymentAccount, &paymentReference); err != nil || paymentAccount != donorID || paymentReference != reference {
						t.Fatal("fresh replay reassigned checkout", paymentAccount, paymentReference, err)
					}
					control["payment_account"], control["recorded_payment_reference"] = paymentAccount, paymentReference
				}
				writePayJSON(t, filepath.Join(evidence, run+"-control.json"), control)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Fixture control received</title></head><body><h1>Fixture control received</h1><a href="/account?billing=return&amp;plan=pro&amp;paid=true&amp;session_id=cs_first">Return to account</a></body></html>`)
				return
			}
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
			receipt := map[string]any{"body": body, "signature": signature, "http_status": webhookStatus, "result": webhookResult, "response_body": string(raw), "body_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(body))), "response_sha256": fmt.Sprintf("%x", sha256.Sum256(raw)), "method": "POST", "path": "/webhooks/stripe", "session_account": ""}
			bindPost(receipt, resp)
			positiveAuthority = map[string]any{"target_account": account, "target_reference": reference, "target_email": a.PrimaryEmail, "payment_intent_created_unix": issued.Unix()}
			writePayJSON(t, filepath.Join(evidence, run+"-webhook.json"), receipt)
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
	input := filepath.Join(evidence, run+"-input.json")
	writePayJSON(t, input, map[string]any{"apex": "https://" + p.config.PublicAddr, "period": period, "width": width, "email": "stranger+" + run + "@example.com", "output": evidence, "scenario": scenario, "run": run})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../scripts/integration-tests/pay-journey-browser.cjs", input)
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("browser journey: %v", err)
	}
	// Retain run bounds and database facts separately from the receipt/report.
	var intents []map[string]any
	rows, err := db.Query(`SELECT reference,account_id,created_at FROM ops_checkout_intents ORDER BY reference`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var reference, account, created string
		if err := rows.Scan(&reference, &account, &created); err != nil {
			t.Fatal(err)
		}
		issued, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			t.Fatal(err)
		}
		intents = append(intents, map[string]any{"reference": reference, "account": account, "created_unix": issued.Unix()})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for _, intent := range intents {
		a, err := local.GetAccount(context.Background(), intent["account"].(string))
		if err != nil || a == nil {
			t.Fatal("capture intent account", err)
		}
		intent["email"] = a.PrimaryEmail
	}
	writePayJSON(t, filepath.Join(evidence, run+"-capture.json"), map[string]any{"run": run, "start_unix": runStart, "end_unix": time.Now().Unix(), "posts": captures, "intents": intents})
	if scenario != "" {
		a, err := local.GetAccount(context.Background(), checkoutAccount)
		var mappings, audits int
		if err != nil || a == nil || a.Plan != "free" || beforePlan != "free" || control == nil {
			t.Fatal("negative control changed plan", a, err)
		}
		wantReads, wantAudits := 1, 1
		if scenario == "unsigned-webhook" {
			wantReads, wantAudits = 0, 0
		} else if scenario == "replayed-checkout" {
			wantReads = 2
		}
		if err := db.QueryRow(`SELECT (SELECT count(*) FROM ops_billing_mappings WHERE account_id=?),(SELECT count(*) FROM ops_billing_events WHERE actor='system:stripe')`, a.ID).Scan(&mappings, &audits); err != nil || mappings != 0 || audits != wantAudits || provider.reads != wantReads {
			t.Fatal("unauthorized billing effects", mappings, audits, provider.reads, err)
		}
		control["target_mappings"], control["automatic_audits"], control["provider_reads"] = mappings, audits, provider.reads
		writePayJSON(t, filepath.Join(evidence, run+"-authority.json"), control)
		return
	}
	a, err := local.GetAccount(context.Background(), checkoutAccount)
	if err != nil || a == nil || a.Plan != "pro" || beforePlan != "free" || provider.reads != 1 || webhookStatus != 200 {
		t.Fatal("payment did not commit Pro", a, err, provider.reads, webhookStatus)
	}
	var mappings, audits int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM ops_billing_mappings WHERE account_id=?),(SELECT count(*) FROM ops_billing_events WHERE actor='system:stripe')`, a.ID).Scan(&mappings, &audits); err != nil || mappings != 1 || audits != 1 {
		t.Fatal("missing durable billing ownership", mappings, audits, err)
	}
	authority := map[string]any{"before_plan": beforePlan, "after_plan": a.Plan, "provider_reads": provider.reads, "provider_transport": "firstCustomerStripeFixture: in-memory, no socket", "mappings": mappings, "automatic_audits": audits, "webhook_status": webhookStatus, "webhook_state": webhookResult.State, "period_seconds": provider.end - provider.start - 10, "width": width}
	for key, value := range positiveAuthority {
		authority[key] = value
	}
	writePayJSON(t, filepath.Join(evidence, run+"-authority.json"), authority)
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
