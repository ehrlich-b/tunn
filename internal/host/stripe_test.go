package host

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
)

func TestVerifyStripeSignature(t *testing.T) {
	secret := "whsec_test_secret"
	payload := []byte(`{"id":"evt_test","type":"customer.subscription.created"}`)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Generate valid signature
	signedPayload := timestamp + "." + string(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	validSig := hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name   string
		header string
		wantOK bool
	}{
		{
			name:   "valid signature",
			header: fmt.Sprintf("t=%s,v1=%s", timestamp, validSig),
			wantOK: true,
		},
		{
			name:   "invalid signature",
			header: fmt.Sprintf("t=%s,v1=%s", timestamp, "invalid"),
			wantOK: false,
		},
		{
			name:   "missing timestamp",
			header: fmt.Sprintf("v1=%s", validSig),
			wantOK: false,
		},
		{
			name:   "missing signature",
			header: fmt.Sprintf("t=%s", timestamp),
			wantOK: false,
		},
		{
			name:   "old timestamp",
			header: fmt.Sprintf("t=%d,v1=%s", time.Now().Unix()-600, validSig),
			wantOK: false,
		},
		{
			name:   "empty header",
			header: "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyStripeSignature(payload, tt.header, secret)
			if got != tt.wantOK {
				t.Errorf("verifyStripeSignature() = %v, want %v", got, tt.wantOK)
			}
		})
	}
}

func TestHandleStripeWebhookNotConfigured(t *testing.T) {
	proxy := &ProxyServer{
		config:         &config.Config{StripeWebhookSecret: ""},
			}

	req := httptest.NewRequest("POST", "/webhooks/stripe", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	proxy.handleStripeWebhook(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}
}

func TestHandleStripeWebhookWrongMethod(t *testing.T) {
	proxy := &ProxyServer{
		config:         &config.Config{StripeWebhookSecret: "test-secret"},
			}

	req := httptest.NewRequest("GET", "/webhooks/stripe", nil)
	rec := httptest.NewRecorder()

	proxy.handleStripeWebhook(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}

func TestHandleStripeWebhookMissingSignature(t *testing.T) {
	proxy := &ProxyServer{
		config:         &config.Config{StripeWebhookSecret: "test-secret"},
			}

	req := httptest.NewRequest("POST", "/webhooks/stripe", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	proxy.handleStripeWebhook(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestHandleStripeWebhookValidEvent(t *testing.T) {
	secret := "whsec_test_secret"
	payload := `{"id":"evt_test","type":"customer.subscription.created","data":{"object":{"id":"sub_123","customer":"cus_456","status":"active"}}}`
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Generate valid signature
	signedPayload := timestamp + "." + payload
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	validSig := hex.EncodeToString(mac.Sum(nil))

	proxy := &ProxyServer{
		config:         &config.Config{StripeWebhookSecret: secret},
			}

	req := httptest.NewRequest("POST", "/webhooks/stripe", strings.NewReader(payload))
	req.Header.Set("Stripe-Signature", fmt.Sprintf("t=%s,v1=%s", timestamp, validSig))
	rec := httptest.NewRecorder()

	proxy.handleStripeWebhook(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}
