package host

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
)

// Exercise the actual HTTP handler, with a fresh Free account and no provider.
// Bad delivery signatures must fail before any durable billing event is written.
func TestPayJourneySignatureDelivery(t *testing.T) {
	p, db := stripeCorrectnessFixture(t)
	local := p.storage.(*storage.LocalStorage)
	p.config.StripeWebhookSecret = "whsec_first_fixture"
	account, err := local.FindOrCreateByEmails(context.Background(), []string{"delivery@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"id":"evt_delivery","created":1,"type":"checkout.session.completed","data":{"object":{"id":"cs_first","customer":"cus_first","subscription":"sub_first","mode":"subscription","payment_status":"paid"}}}`
	now := time.Now().Unix()
	for _, timestamp := range []int64{1, now - 3600, now + 3600} {
		t.Run(fmt.Sprint(timestamp-now), func(t *testing.T) {
			response := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, timestamp))
			if response.Code != 400 || response.Body.String() != "Invalid signature\n" {
				t.Fatal(response.Code, response.Body.String())
			}
		})
	}
	for _, header := range []string{"", "t=no,v1=" + strings.Repeat("a", 64), "v1=" + strings.Repeat("a", 64)} {
		response := stripeFixtureRequest(p, body, header)
		if response.Code != 400 {
			t.Fatal(response.Code, response.Body.String())
		}
	}
	current, err := local.GetAccount(context.Background(), account.ID)
	var events int
	if err != nil || current.Plan != "free" {
		t.Fatal(current, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM ops_billing_events`).Scan(&events); err != nil || events != 0 {
		t.Fatal(events, err)
	}
	t.Log("real handler rejected expired/future/nonnumeric/missing signatures: account remains Free; zero durable billing events")
}
