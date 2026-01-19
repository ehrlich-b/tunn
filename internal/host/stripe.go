package host

import (
	"context"
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

	ctx := r.Context()

	// Handle the event
	switch event.Type {
	case "checkout.session.completed":
		// Best event for upgrades - has customer_email directly
		if err := p.handleCheckoutCompleted(ctx, event); err != nil {
			common.LogError("failed to handle checkout completed", "error", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

	case "customer.subscription.deleted":
		// Subscription cancelled - downgrade to free
		if err := p.handleSubscriptionDeleted(ctx, event); err != nil {
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

// handleCheckoutCompleted processes checkout.session.completed events
// This is the best event for upgrades because it has customer_email directly
func (p *ProxyServer) handleCheckoutCompleted(ctx context.Context, event StripeEvent) error {
	var session StripeCheckoutSession
	if err := json.Unmarshal(event.Data.Object, &session); err != nil {
		return fmt.Errorf("failed to parse checkout session: %w", err)
	}

	// Only handle subscription checkouts
	if session.Mode != "subscription" {
		common.LogInfo("ignoring non-subscription checkout", "mode", session.Mode)
		return nil
	}

	// Try multiple sources for email:
	// 1. customer_email (pre-filled)
	// 2. customer_details.email (entered during checkout)
	// 3. Look up customer from Stripe API
	email := session.CustomerEmail
	if email == "" && session.CustomerDetails != nil {
		email = session.CustomerDetails.Email
	}
	if email == "" && session.Customer != "" {
		var err error
		email, err = p.getStripeCustomerEmail(ctx, session.Customer)
		if err != nil {
			common.LogError("failed to get customer email from Stripe", "error", err)
		}
	}
	if email == "" {
		common.LogError("checkout session missing customer email", "session_id", session.ID)
		return fmt.Errorf("missing customer email")
	}

	common.LogInfo("processing checkout completed",
		"session_id", session.ID,
		"email", email,
		"customer_id", session.Customer,
	)

	// Find or create account - if someone pays without signing up first, create their account
	account, err := p.storage.FindOrCreateByEmails(ctx, []string{email}, "stripe")
	if err != nil {
		return fmt.Errorf("failed to find/create account: %w", err)
	}

	// Upgrade to pro
	if err := p.storage.UpdatePlan(ctx, account.ID, "pro"); err != nil {
		return fmt.Errorf("failed to update plan: %w", err)
	}

	common.LogInfo("upgraded account to pro",
		"account_id", account.ID,
		"email", email,
	)

	return nil
}

// handleSubscriptionDeleted processes customer.subscription.deleted events
func (p *ProxyServer) handleSubscriptionDeleted(ctx context.Context, event StripeEvent) error {
	var subscription StripeSubscription
	if err := json.Unmarshal(event.Data.Object, &subscription); err != nil {
		return fmt.Errorf("failed to parse subscription: %w", err)
	}

	common.LogInfo("processing subscription deleted",
		"subscription_id", subscription.ID,
		"customer_id", subscription.Customer,
	)

	// Need to look up customer email from Stripe
	email, err := p.getStripeCustomerEmail(ctx, subscription.Customer)
	if err != nil {
		return fmt.Errorf("failed to get customer email: %w", err)
	}

	// Find account by email
	account, err := p.storage.GetAccountByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to get account: %w", err)
	}
	if account == nil {
		common.LogError("no account found for customer email", "email", email)
		return nil // Don't error
	}

	// Downgrade to free
	if err := p.storage.UpdatePlan(ctx, account.ID, "free"); err != nil {
		return fmt.Errorf("failed to update plan: %w", err)
	}

	common.LogInfo("downgraded account to free",
		"account_id", account.ID,
		"email", email,
	)

	return nil
}

// getStripeCustomerEmail fetches a customer's email from Stripe API
func (p *ProxyServer) getStripeCustomerEmail(ctx context.Context, customerID string) (string, error) {
	if p.config.StripeSecretKey == "" {
		return "", fmt.Errorf("STRIPE_SECRET_KEY not configured")
	}

	url := fmt.Sprintf("https://api.stripe.com/v1/customers/%s", customerID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(p.config.StripeSecretKey, "")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("stripe API error: %d %s", resp.StatusCode, string(body))
	}

	var customer StripeCustomer
	if err := json.NewDecoder(resp.Body).Decode(&customer); err != nil {
		return "", err
	}

	return customer.Email, nil
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
