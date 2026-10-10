package host

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

type billingCommitFailure struct{ storage.Storage }

func (billingCommitFailure) ProcessBillingEvent(context.Context, store.BillingEvent) (*store.BillingResult, error) {
	return nil, errors.New("fixture commit failure")
}

func TestAccountOperationsStripeConfiguredCommitRequired(t *testing.T) {
	local := securityDB(t)
	for _, tt := range []struct {
		name      string
		storage   storage.Storage
		eventType string
		want      int
	}{
		{"no authority for checkout", nil, "checkout.session.completed", http.StatusServiceUnavailable},
		{"no authority for cancellation", nil, "customer.subscription.deleted", http.StatusServiceUnavailable},
		{"configured authority unavailable", storage.NewProxyStorage(), "customer.subscription.created", http.StatusServiceUnavailable},
		{"configured authority lacks processor", struct{ storage.Storage }{local}, "customer.subscription.created", http.StatusServiceUnavailable},
		{"configured commit fails", billingCommitFailure{local}, "customer.subscription.created", http.StatusServiceUnavailable},
		{"configured creation commits", local, "customer.subscription.created", http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &ProxyServer{storage: tt.storage, config: &config.Config{StripeWebhookSecret: "whsec_commit_fixture"}}
			body := fmt.Sprintf(`{"id":"evt_commit_fixture","type":%q,"data":{"object":{"id":"sub_fixture","customer":"cus_fixture","subscription":"sub_fixture","mode":"subscription","status":"active"}}}`, tt.eventType)
			for repeat := 0; repeat < 2; repeat++ {
				r := httptest.NewRequest(http.MethodPost, "/webhooks/stripe", strings.NewReader(body))
				timestamp := fmt.Sprint(time.Now().Unix())
				mac := hmac.New(sha256.New, []byte(p.config.StripeWebhookSecret))
				_, _ = mac.Write([]byte(timestamp + "." + body))
				r.Header.Set("Stripe-Signature", "t="+timestamp+",v1="+hex.EncodeToString(mac.Sum(nil)))
				w := httptest.NewRecorder()
				p.handleStripeWebhook(w, r)
				if w.Code != tt.want {
					t.Fatalf("webhook status=%d want=%d body=%s", w.Code, tt.want, w.Body.String())
				}
				if tt.want == http.StatusOK {
					var result store.BillingResult
					if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.State != "reconciliation_required" || result.Duplicate != (repeat == 1) {
						t.Fatalf("creation was not durably recorded: %+v err=%v", result, err)
					}
				}
			}
		})
	}
}
