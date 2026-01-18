package host

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
)

// StripeEvent represents a Stripe webhook event
type StripeEvent struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Data     StripeEventData `json:"data"`
	Created  int64           `json:"created"`
	Livemode bool            `json:"livemode"`
}

// StripeEventData contains the event data object
type StripeEventData struct {
	Object json.RawMessage `json:"object"`
}

// StripeSubscription represents a Stripe subscription object
type StripeSubscription struct {
	ID       string `json:"id"`
	Customer string `json:"customer"`
	Status   string `json:"status"`
}

// StripeCustomer represents a Stripe customer object
type StripeCustomer struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// handleStripeWebhook handles POST /webhooks/stripe
func (p *ProxyServer) handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if Stripe is configured
	if p.config.StripeWebhookSecret == "" {
		common.LogError("Stripe webhook received but STRIPE_WEBHOOK_SECRET not configured")
		http.Error(w, "Stripe not configured", http.StatusServiceUnavailable)
		return
	}

	// Check if storage is available (Stripe will retry on 503)
	if p.storage != nil && !p.storage.Available() {
		common.LogError("Stripe webhook received but storage not available")
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	// Read the request body
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536)) // 64KB limit
	if err != nil {
		common.LogError("failed to read webhook body", "error", err)
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Verify the signature
	signature := r.Header.Get("Stripe-Signature")
	if signature == "" {
		common.LogError("missing Stripe-Signature header")
		http.Error(w, "Missing signature", http.StatusBadRequest)
		return
	}

	if !verifyStripeSignature(body, signature, p.config.StripeWebhookSecret) {
		common.LogError("invalid Stripe signature")
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	// Parse the event
	var event StripeEvent
	if err := json.Unmarshal(body, &event); err != nil {
		common.LogError("failed to parse Stripe event", "error", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	common.LogInfo("received Stripe webhook", "type", event.Type, "id", event.ID)

	// Handle the event
	switch event.Type {
	case "customer.subscription.created", "customer.subscription.updated":
		if err := p.handleSubscriptionEvent(event, true); err != nil {
			common.LogError("failed to handle subscription event", "error", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

	case "customer.subscription.deleted":
		if err := p.handleSubscriptionEvent(event, false); err != nil {
			common.LogError("failed to handle subscription deletion", "error", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

	default:
		common.LogInfo("ignoring unhandled Stripe event", "type", event.Type)
	}

	// Return success
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"received": true}`))
}

// handleSubscriptionEvent processes subscription created/updated/deleted events
func (p *ProxyServer) handleSubscriptionEvent(event StripeEvent, isPro bool) error {
	// Parse the subscription object
	var subscription StripeSubscription
	if err := json.Unmarshal(event.Data.Object, &subscription); err != nil {
		return fmt.Errorf("failed to parse subscription: %w", err)
	}

	// For subscription.created/updated, only upgrade if status is active
	if isPro && subscription.Status != "active" && subscription.Status != "trialing" {
		common.LogInfo("ignoring subscription with non-active status", "status", subscription.Status)
		return nil
	}

	// Get customer email - we need to look it up from Stripe
	// For now, we'll store customer_id -> email mapping in metadata
	// In production, you'd typically call Stripe API to get customer email
	// or include customer email in subscription metadata

	// The customer field contains the customer ID, not email
	// We need the email to find the account
	// For simplicity, we'll assume the customer email is stored in subscription metadata
	// or we can look it up via Stripe API if needed

	common.LogInfo("subscription event processed",
		"subscription_id", subscription.ID,
		"customer_id", subscription.Customer,
		"status", subscription.Status,
		"is_pro", isPro,
	)

	// TODO: To complete this, we need either:
	// 1. Customer email in subscription metadata (Stripe Checkout can add this)
	// 2. Call Stripe API to get customer email: GET /v1/customers/{id}
	// 3. Store customer_id -> account_id mapping when checkout is created

	// For now, log and return success - the actual account update
	// will require the email lookup logic above
	return nil
}

// verifyStripeSignature verifies the Stripe webhook signature
// Uses the Stripe-Signature header format: t=timestamp,v1=signature
func verifyStripeSignature(payload []byte, header, secret string) bool {
	// Parse the signature header
	var timestamp string
	var signatures []string

	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
			signatures = append(signatures, kv[1])
		}
	}

	if timestamp == "" || len(signatures) == 0 {
		return false
	}

	// Check timestamp is within tolerance (5 minutes)
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix()-ts > 300 {
		common.LogError("Stripe signature timestamp too old", "timestamp", timestamp)
		return false
	}

	// Compute expected signature
	signedPayload := timestamp + "." + string(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	// Compare with provided signatures
	for _, sig := range signatures {
		if hmac.Equal([]byte(sig), []byte(expectedSig)) {
			return true
		}
	}

	return false
}
