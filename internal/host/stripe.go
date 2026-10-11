package host

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/store"
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

// StripeCheckoutSession represents a Stripe checkout session object
type StripeCheckoutSession struct {
	ID              string                 `json:"id"`
	Customer        string                 `json:"customer"`
	CustomerEmail   string                 `json:"customer_email"`
	CustomerDetails *StripeCustomerDetails `json:"customer_details"`
	Mode            string                 `json:"mode"` // "subscription" or "payment"
	Status          string                 `json:"status"`
}

// StripeCustomerDetails contains customer info from checkout
type StripeCustomerDetails struct {
	Email string `json:"email"`
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
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536)) // 64KB limit
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

	eventMetadata, err := normalizeStripeEvent(event, body)
	if err != nil {
		http.Error(w, "Invalid billing metadata", 400)
		return
	}
	// Preserve receipt of historically ignored notifications when no account
	// service is configured. NewProxyServer always installs local or proxy
	// storage, so configured billing still requires a durable commit below.
	if p.storage == nil && (!eventMetadata.Supported || event.Type == "customer.subscription.created" || event.Type == "customer.subscription.updated") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&store.BillingResult{EventID: event.ID, State: "ignored"})
		return
	}
	processor, ok := p.storage.(interface {
		ProcessBillingEvent(context.Context, store.BillingEvent) (*store.BillingResult, error)
	})
	if !ok {
		http.Error(w, "Billing authority unavailable", http.StatusServiceUnavailable)
		return
	}
	result, err := processor.ProcessBillingEvent(r.Context(), eventMetadata)
	if err != nil {
		http.Error(w, "Billing event not committed", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// Stripe provides no authoritative per-subscription event revision. All
// supported lifecycle events await an operator-supplied authoritative snapshot.
// Email, metadata.account_id, checkout completion and arrival order confer no
// entitlement and cannot create or reassign an account.
func normalizeStripeEvent(event StripeEvent, body []byte) (store.BillingEvent, error) {
	digest := sha256.Sum256(body)
	out := store.BillingEvent{Provider: "stripe", ID: event.ID, Type: event.Type, PayloadSHA256: hex.EncodeToString(digest[:])}
	switch event.Type {
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
		var sub StripeSubscription
		if err := json.Unmarshal(event.Data.Object, &sub); err != nil {
			return out, err
		}
		out.CustomerID, out.SubscriptionID, out.Supported = sub.Customer, sub.ID, true
	case "checkout.session.completed":
		var session struct {
			Customer     string `json:"customer"`
			Subscription string `json:"subscription"`
			Mode         string `json:"mode"`
			Reference    string `json:"client_reference_id"`
		}
		if err := json.Unmarshal(event.Data.Object, &session); err != nil {
			return out, err
		}
		out.CustomerID, out.SubscriptionID, out.Supported = session.Customer, session.Subscription, session.Mode == "subscription"
		out.CheckoutReference = session.Reference
	}
	return out, nil
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
	now := time.Now().Unix()
	if ts < now-300 || ts > now+300 {
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
