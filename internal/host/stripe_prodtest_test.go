package host

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

func stripeCorrectnessFixture(t *testing.T) (*ProxyServer, *sql.DB) {
	t.Helper()
	db, err := store.OpenLocal(filepath.Join(t.TempDir(), "stripe.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &ProxyServer{config: securityConfig(), storage: storage.NewLocalStorage(db)}, db
}

func signedStripeFixture(body, secret string, timestamp int64) string {
	ts := strconv.FormatInt(timestamp, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ts + "." + body))
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func stripeFixtureRequest(p *ProxyServer, body, signature string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://tunn.test/webhooks/stripe", strings.NewReader(body))
	r.Header.Set("Stripe-Signature", signature)
	w := httptest.NewRecorder()
	p.handleStripeWebhook(w, r)
	return w
}

func TestStripeSignatureDeliveryTable(t *testing.T) {
	const body = `{"id":"signature","type":"invoice.future","data":{"object":{}}}`
	const secret = "whsec_signature_fixture"
	for _, tc := range []struct {
		name    string
		header  func() string
		payload string
		want    int
	}{
		{"valid", func() string { return signedStripeFixture(body, secret, time.Now().Unix()) }, body, 200},
		{"rotated_signature", func() string { return signedStripeFixture(body, secret, time.Now().Unix()) + ",v1=invalid" }, body, 200},
		{"new_signature_after_old", func() string { return "v1=invalid," + signedStripeFixture(body, secret, time.Now().Unix()) }, body, 200},
		{"missing", func() string { return "" }, body, 400},
		{"wrong_secret", func() string { return signedStripeFixture(body, "whsec_other", time.Now().Unix()) }, body, 400},
		{"old_timestamp", func() string { return signedStripeFixture(body, secret, time.Now().Unix()-900) }, body, 400},
		{"future_timestamp", func() string { return signedStripeFixture(body, secret, time.Now().Unix()+900) }, body, 400},
		{"missing_timestamp", func() string { return "v1=012345" }, body, 400},
		{"nonnumeric_timestamp", func() string { return "t=tomorrow,v1=012345" }, body, 400},
		{"unsupported_version", func() string {
			return strings.Replace(signedStripeFixture(body, secret, time.Now().Unix()), "v1=", "v0=", 1)
		}, body, 400},
		{"changed_body", func() string { return signedStripeFixture(body, secret, time.Now().Unix()) }, body + " ", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, db := stripeCorrectnessFixture(t)
			p.config.StripeWebhookSecret = secret
			w := stripeFixtureRequest(p, tc.payload, tc.header())
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
			var count int
			if err := db.QueryRow("SELECT count(*) FROM ops_billing_events").Scan(&count); err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			if tc.want == 200 {
				wantCount = 1
			}
			if count != wantCount {
				t.Fatalf("signature result committed %d rows, want %d", count, wantCount)
			}
		})
	}
}

func TestStripeSignedPayloadParsingAndSizeBoundary(t *testing.T) {
	const base = `{"id":"payload","type":"invoice.future","data":{"object":{}}}`
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"invalid_json", "{", 400},
		{"wrong_subscription_object", `{"id":"bad_sub","type":"customer.subscription.updated","data":{"object":42}}`, 400},
		{"wrong_checkout_customer", `{"id":"bad_checkout","type":"checkout.session.completed","data":{"object":{"customer":42,"mode":"subscription"}}}`, 400},
		{"second_json_value", base + base, 400},
		{"exact_limit", base + strings.Repeat(" ", 65536-len(base)), 200},
		{"above_limit", base + strings.Repeat(" ", 65537-len(base)), 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, db := stripeCorrectnessFixture(t)
			p.config.StripeWebhookSecret = "whsec_payload_fixture"
			w := stripeFixtureRequest(p, tc.body, signedStripeFixture(tc.body, p.config.StripeWebhookSecret, time.Now().Unix()))
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
			var count int
			if err := db.QueryRow("SELECT count(*) FROM ops_billing_events").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if (count == 1) != (tc.want == 200) {
				t.Fatalf("unexpected durable event count: %d", count)
			}
		})
	}
}

func TestStripeLifecycleOrderAndRestartDoNotGrantEntitlements(t *testing.T) {
	for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stripe.db")
			db, err := store.OpenLocal(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			local := storage.NewLocalStorage(db)
			ctx := context.Background()
			a, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.invalid"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			ops := local.OperationsStore()
			admin := accountOperationsAdmin(t, a.ID)
			if err := ops.BindBilling(ctx, admin, store.BillingMapping{Provider: "stripe", CustomerID: "cus_fixed", SubscriptionID: "sub_fixed", AccountID: a.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err := ops.Transition(ctx, admin, a.ID, "suspended", "billing review", 0); err != nil {
				t.Fatal(err)
			}
			cfg := securityConfig()
			cfg.StripeWebhookSecret = "whsec_lifecycle_fixture"
			p := &ProxyServer{config: cfg, storage: local}
			bodies := []string{
				`{"id":"checkout","type":"checkout.session.completed","created":300,"data":{"object":{"customer":"cus_fixed","subscription":"sub_fixed","mode":"subscription","customer_email":"untrusted@example.invalid","metadata":{"account_id":"untrusted"}}}}`,
				`{"id":"updated","type":"customer.subscription.updated","created":200,"data":{"object":{"id":"sub_fixed","customer":"cus_fixed","status":"active"}}}`,
				`{"id":"deleted","type":"customer.subscription.deleted","created":100,"data":{"object":{"id":"sub_fixed","customer":"cus_fixed","status":"canceled"}}}`,
			}
			check := func(body string, duplicate bool) {
				t.Helper()
				w := stripeFixtureRequest(p, body, signedStripeFixture(body, cfg.StripeWebhookSecret, time.Now().Unix()))
				var result store.BillingResult
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.State != "reconciliation_required" || result.AccountID != a.ID || result.Duplicate != duplicate {
					t.Fatalf("receipt status=%d result=%+v body=%s", w.Code, result, w.Body.String())
				}
			}
			for _, i := range order {
				check(bodies[i], false)
				check(bodies[i], true)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = store.OpenLocal(path)
			if err != nil {
				t.Fatal(err)
			}
			local = storage.NewLocalStorage(db)
			p.storage = local
			for _, body := range bodies {
				check(body, true)
			}
			changed := strings.Replace(bodies[1], `"active"`, `"past_due"`, 1)
			if w := stripeFixtureRequest(p, changed, signedStripeFixture(changed, cfg.StripeWebhookSecret, time.Now().Unix())); w.Code != 503 {
				t.Fatalf("conflicting event ID acknowledged: %d %s", w.Code, w.Body.String())
			}
			account, err := local.GetAccountByEmail(ctx, a.PrimaryEmail)
			if err != nil || account.Plan != "free" || account.OperationalState != "suspended" || account.OperationalVersion != 1 {
				t.Fatalf("unordered Stripe events changed account: %+v %v", account, err)
			}
			var count, version int
			if err := db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); err != nil || count != 1 {
				t.Fatalf("unexpected accounts: %d %v", count, err)
			}
			if err := db.QueryRow("SELECT count(*) FROM ops_billing_events").Scan(&count); err != nil || count != 3 {
				t.Fatalf("unexpected events: %d %v", count, err)
			}
			if err := db.QueryRow("SELECT version FROM ops_billing_mappings").Scan(&version); err != nil || version != 0 {
				t.Fatalf("mapping changed: %d %v", version, err)
			}
		})
	}
}
