package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
)

func TestLegacySignedBodyConflict(t *testing.T) {
	for _, typ := range []string{"charge.refunded", "charge.dispute.created", "invoice.paid", "invoice.payment_succeeded"} {
		t.Run(typ, func(t *testing.T) {
			p, db := stripeCorrectnessFixture(t)
			p.config.StripeWebhookSecret = "whsec_sol_local_fixture"
			body := fmt.Sprintf(`{"id":"evt_legacy","type":%q,"data":{"object":{"id":"ch_fixture"}}}`, typ)
			var event StripeEvent
			if err := json.Unmarshal([]byte(body), &event); err != nil {
				t.Fatal(err)
			}
			old, err := solBaseNormalizeStripeEvent(event, []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.NewOperationsStore(db, nil).ProcessBillingEvent(context.Background(), old); err != nil {
				t.Fatal(err)
			}
			altered := fmt.Sprintf(`{"id":"evt_legacy","type":%q,"data":{"object":{"id":"ch_changed"}}}`, typ)
			response := stripeFixtureRequest(p, altered, signedStripeFixture(altered, p.config.StripeWebhookSecret, time.Now().Unix()))
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("changed signed body: HTTP %d: %s", response.Code, response.Body)
			}
		})
	}
}
