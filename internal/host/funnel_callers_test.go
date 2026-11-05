package host

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

func assertFunnelStage(t *testing.T, db *sql.DB, stage string, want int) {
	t.Helper()
	rows, err := db.Query(`SELECT stage,account_hash,occurred_at FROM funnel_events WHERE stage=?`, stage)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var stage, hash, stamp string
		if err := rows.Scan(&stage, &hash, &stamp); err != nil {
			t.Fatal(err)
		}
		if len(hash) != 64 || strings.ContainsAny(stage+hash+stamp, "@/?") {
			t.Fatalf("unsafe row: %q %q %q", stage, hash, stamp)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Fatalf("%s rows=%d want=%d", stage, n, want)
	}
}

func failFunnelWrites(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`CREATE TRIGGER fail_funnel BEFORE INSERT ON funnel_events BEGIN SELECT RAISE(ABORT,'fixture write failure'); END`); err != nil {
		t.Fatal(err)
	}
}

func TestFunnelStageCallers(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name, want := "record", 1
		if fail {
			name, want = "write_failure", 0
		}
		t.Run(name, func(t *testing.T) {
			t.Run("signup", func(t *testing.T) {
				p, db := stripeCorrectnessFixture(t)
				if fail {
					failFunnelWrites(t, db)
				}
				p.emailSender = new(accountsMailCapture)
				if w := magicFixturePost(p, "", `{"email":"owner@example.invalid"}`); w.Code != 200 {
					t.Fatal(w.Code, w.Body)
				}
				link := p.emailSender.(*accountsMailCapture).link
				w := httptest.NewRecorder()
				p.handleMagicLinkVerify(w, httptest.NewRequest(http.MethodGet, link, nil))
				if w.Code != 302 {
					t.Fatal(w.Code, w.Body)
				}
				local := p.storage.(*storage.LocalStorage)
				for i := 0; i < 2; i++ {
					if _, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.invalid"}, "fixture"); err != nil {
						t.Fatal(err)
					}
					assertFunnelStage(t, db, "signup", want)
				}
			})
			t.Run("mcp_consent", func(t *testing.T) {
				f := newMCPOAuthFixture(t)
				db := f.p.mcpOAuth.db
				if fail {
					failFunnelWrites(t, db)
				}
				c := discoverMCPClient(t, f)
				for i := 0; i < 2; i++ {
					c.code(t)
					assertFunnelStage(t, db, "mcp_consent", want)
				}
			})
			t.Run("checkout_start_and_pro_active", func(t *testing.T) {
				p, db := stripeCorrectnessFixture(t)
				p.Domain, p.config.Domain = "tunn.to", "tunn.to"
				p.config.BillingEnabled, p.config.StripeWebhookSecret = true, "whsec_funnel"
				p.config.StripeCheckoutURLMonthly = "https://buy.stripe.com/funnel"
				local := p.storage.(*storage.LocalStorage)
				account, err := local.FindOrCreateByEmails(context.Background(), []string{"owner+demo@example.com"}, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				if fail {
					failFunnelWrites(t, db)
				}
				for i := 0; i < 2; i++ {
					if w := revenueRequest(t, p, "/upgrade?period=monthly", true); w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "https://buy.stripe.com/") {
						t.Fatal(w.Code, w.Header())
					}
					assertFunnelStage(t, db, "checkout_start", want)
				}
				ctx := context.Background()
				ops, admin := local.OperationsStore(), accountOperationsAdmin(t, account.ID)
				if err := ops.BindBilling(ctx, admin, store.BillingMapping{Provider: "stripe", CustomerID: "cus_funnel", SubscriptionID: "sub_funnel", AccountID: account.ID}); err != nil {
					t.Fatal(err)
				}
				body := `{"id":"evt_funnel","type":"checkout.session.completed","data":{"object":{"id":"cs_funnel","mode":"subscription","customer":"cus_funnel","subscription":"sub_funnel"}}}`
				for i := 0; i < 2; i++ {
					w := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix()))
					if w.Code != 200 {
						t.Fatal(w.Code, w.Body)
					}
					assertFunnelStage(t, db, "checkout_completed", want)
				}
				snap := store.BillingSnapshot{Provider: "stripe", CustomerID: "cus_funnel", SubscriptionID: "sub_funnel", AccountID: account.ID, Plan: "pro", EventIDs: []string{"evt_funnel"}, ProviderReadAt: time.Now(), EvidenceSHA256: strings.Repeat("d", 64), PriceID: "price_approved", ProviderStatus: "active", PaymentConfirmed: true}
				for i := 0; i < 2; i++ {
					if _, err := ops.ApplyReviewedBilling(ctx, admin, []store.BillingSnapshot{snap}); err != nil {
						t.Fatal(err)
					}
					a, err := local.AccountStore().GetByID(account.ID)
					if err != nil || a.Plan != "pro" {
						t.Fatalf("account=%+v err=%v", a, err)
					}
					assertFunnelStage(t, db, "pro_active", want)
					snap.ExpectedVersion++
				}
			})
		})
	}
}

func TestFunnelRejectedTunnel(t *testing.T) {
	for _, target := range []string{"web", "mcp"} {
		t.Run(target, func(t *testing.T) {
			f := newDurablePublisherFixture(t)
			sharing := &recoveringRegistrationSharing{SharingBackend: f.login.sharingBackend()}
			sharing.unavailable.Store(true)
			f.relay.tunnelServer.SetSharingBackend(sharing)
			f.publisher.EndpointProtocol, f.publisher.RequireSharing = "http", true
			want := "Web permission authority unavailable."
			if target == "mcp" {
				f.publisher.PublicPath, want = "/mcp", "Endpoint policy authority unavailable."
			}
			db := f.login.devices.db
			recoverRegistration(t, f, want, func() {
				assertFunnelStage(t, db, "tunnel", 0)
				sharing.unavailable.Store(false)
			})
			// The successful response precedes the login node's availability RPC.
			deadline := time.Now().Add(2 * time.Second)
			for {
				var n int
				if err := db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='tunnel'`).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n == 1 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("successful admission missing funnel event")
				}
				time.Sleep(10 * time.Millisecond)
			}
			conn, _ := f.relay.tunnelServer.GetTunnel(f.publisher.TunnelID)
			for i := 0; i < 2; i++ {
				if err := f.relay.tunnelServer.reportAvailability(conn, "up", ""); err != nil {
					t.Fatal(err)
				}
				assertFunnelStage(t, db, "tunnel", 1)
			}
		})
	}
}
