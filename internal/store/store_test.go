package store

import (
	"os"
	"testing"
	"time"
)

func TestDeviceCodeStore(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}
	defer db.Close()

	store := NewDeviceCodeStore(db)

	// Create a device code
	code, err := store.Create()
	if err != nil {
		t.Fatalf("failed to create device code: %v", err)
	}

	if code.Code == "" {
		t.Error("expected non-empty device code")
	}
	if code.UserCode == "" {
		t.Error("expected non-empty user code")
	}
	if code.Authorized {
		t.Error("expected code to not be authorized initially")
	}

	// Get by code
	retrieved := store.Get(code.Code)
	if retrieved == nil {
		t.Fatal("expected to retrieve device code")
	}
	if retrieved.Code != code.Code {
		t.Errorf("expected code %s, got %s", code.Code, retrieved.Code)
	}

	// Get by user code
	retrieved = store.GetByUserCode(code.UserCode)
	if retrieved == nil {
		t.Fatal("expected to retrieve device code by user code")
	}
	if retrieved.UserCode != code.UserCode {
		t.Errorf("expected user code %s, got %s", code.UserCode, retrieved.UserCode)
	}

	// Authorize
	ok := store.Authorize(code.Code, "test@example.com")
	if !ok {
		t.Error("expected authorization to succeed")
	}

	retrieved = store.Get(code.Code)
	if !retrieved.Authorized {
		t.Error("expected code to be authorized")
	}
	if retrieved.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", retrieved.Email)
	}

	// Delete
	store.Delete(code.Code)
	retrieved = store.Get(code.Code)
	if retrieved != nil {
		t.Error("expected code to be deleted")
	}
}

func TestAccountStore(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}
	defer db.Close()

	store := NewAccountStore(db)

	// Create account with new emails
	emails := []string{"alice@example.com", "alice@work.com"}
	account, err := store.FindOrCreateByEmails(emails, "github")
	if err != nil {
		t.Fatalf("failed to create account: %v", err)
	}

	if account.ID == "" {
		t.Error("expected non-empty account ID")
	}
	if account.Plan != "free" {
		t.Errorf("expected plan 'free', got %s", account.Plan)
	}
	if len(account.Emails) != 2 {
		t.Errorf("expected 2 emails, got %d", len(account.Emails))
	}

	// Find existing account
	account2, err := store.FindOrCreateByEmails([]string{"alice@example.com"}, "github")
	if err != nil {
		t.Fatalf("failed to find account: %v", err)
	}
	if account2.ID != account.ID {
		t.Error("expected same account ID for existing email")
	}

	// Get by email
	account3, err := store.GetByEmail("alice@work.com")
	if err != nil {
		t.Fatalf("failed to get by email: %v", err)
	}
	if account3.ID != account.ID {
		t.Error("expected same account ID")
	}

	// Get email bucket
	bucket, err := store.GetEmailBucket("alice@example.com")
	if err != nil {
		t.Fatalf("failed to get email bucket: %v", err)
	}
	if len(bucket) != 2 {
		t.Errorf("expected 2 emails in bucket, got %d", len(bucket))
	}

	// Update plan
	err = store.UpdatePlan(account.ID, "pro")
	if err != nil {
		t.Fatalf("failed to update plan: %v", err)
	}

	account4, err := store.GetByEmail("alice@example.com")
	if err != nil {
		t.Fatalf("failed to get account after update: %v", err)
	}
	if account4.Plan != "pro" {
		t.Errorf("expected plan 'pro', got %s", account4.Plan)
	}
}

func TestAccountMerge(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}
	defer db.Close()

	store := NewAccountStore(db)

	// Create two separate accounts
	account1, err := store.FindOrCreateByEmails([]string{"bob@personal.com"}, "github")
	if err != nil {
		t.Fatalf("failed to create account1: %v", err)
	}

	account2, err := store.FindOrCreateByEmails([]string{"bob@work.com"}, "github")
	if err != nil {
		t.Fatalf("failed to create account2: %v", err)
	}

	if account1.ID == account2.ID {
		t.Error("expected different account IDs")
	}

	// Update account2 to pro
	store.UpdatePlan(account2.ID, "pro")

	// Now "link" both emails via GitHub OAuth - should merge
	merged, err := store.FindOrCreateByEmails([]string{"bob@personal.com", "bob@work.com"}, "github")
	if err != nil {
		t.Fatalf("failed to merge accounts: %v", err)
	}

	// Should keep the pro plan
	if merged.Plan != "pro" {
		t.Errorf("expected merged account to have 'pro' plan, got %s", merged.Plan)
	}

	// Both emails should be in the bucket
	if len(merged.Emails) != 2 {
		t.Errorf("expected 2 emails after merge, got %d", len(merged.Emails))
	}
}

func TestUserCodeFormat(t *testing.T) {
	code, err := generateUserCode()
	if err != nil {
		t.Fatalf("failed to generate user code: %v", err)
	}

	if len(code) != 7 {
		t.Errorf("expected user code length 7, got %d", len(code))
	}

	if code[3] != '-' {
		t.Errorf("expected hyphen at position 3, got %c", code[3])
	}
}

func TestUserStore(t *testing.T) {
	// Create a temporary users.yaml file
	content := `
alice@example.com:
  token: "tunn_sk_alice123"
  plan: "pro"
bob@example.com:
  token: "tunn_sk_bob456"
  plan: "free"
`
	tmpFile, err := os.CreateTemp("", "users-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Load the user store
	store, err := NewUserStore(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load user store: %v", err)
	}

	if store.Count() != 2 {
		t.Errorf("expected 2 users, got %d", store.Count())
	}

	// Test ValidateToken
	email, ok := store.ValidateToken("tunn_sk_alice123")
	if !ok {
		t.Error("expected token to be valid")
	}
	if email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %s", email)
	}

	// Test invalid token
	_, ok = store.ValidateToken("invalid-token")
	if ok {
		t.Error("expected invalid token to fail")
	}

	// Test GetUser
	user := store.GetUser("bob@example.com")
	if user == nil {
		t.Fatal("expected to find bob")
	}
	if user.Plan != "free" {
		t.Errorf("expected plan 'free', got %s", user.Plan)
	}

	// Test GetTokenMap
	tokenMap := store.GetTokenMap()
	if len(tokenMap) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokenMap))
	}
	if tokenMap["alice@example.com"] != "tunn_sk_alice123" {
		t.Errorf("expected alice's token, got %s", tokenMap["alice@example.com"])
	}
}

func TestDeviceCodeExpiration(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}
	defer db.Close()

	// Insert an already expired code directly
	_, err = db.Exec(
		"INSERT INTO device_codes (code, user_code, expires_at, authorized) VALUES (?, ?, ?, 0)",
		"expired-code", "EXP-IRE", time.Now().Add(-1*time.Hour).Unix(),
	)
	if err != nil {
		t.Fatalf("failed to insert expired code: %v", err)
	}

	store := NewDeviceCodeStore(db)

	// Should not retrieve expired code
	code := store.Get("expired-code")
	if code != nil {
		t.Error("expected nil for expired code")
	}

	code = store.GetByUserCode("EXP-IRE")
	if code != nil {
		t.Error("expected nil for expired code by user code")
	}
}

func TestSubdomainReservation(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}
	defer db.Close()

	store := NewAccountStore(db)

	// Create a Pro account
	account, err := store.FindOrCreateByEmails([]string{"pro@example.com"}, "github")
	if err != nil {
		t.Fatalf("failed to create account: %v", err)
	}
	if err := store.UpdatePlan(account.ID, "pro"); err != nil {
		t.Fatalf("failed to update plan: %v", err)
	}

	// Reserve a subdomain
	err = store.ReserveSubdomain(account.ID, "myapp")
	if err != nil {
		t.Fatalf("failed to reserve subdomain: %v", err)
	}

	// Check ownership
	owner, err := store.GetSubdomainOwner("myapp")
	if err != nil {
		t.Fatalf("failed to get owner: %v", err)
	}
	if owner != account.ID {
		t.Errorf("expected owner %s, got %s", account.ID, owner)
	}

	// Get reserved subdomains
	reserved, err := store.GetReservedSubdomains(account.ID)
	if err != nil {
		t.Fatalf("failed to get reserved subdomains: %v", err)
	}
	if len(reserved) != 1 {
		t.Errorf("expected 1 reserved subdomain, got %d", len(reserved))
	}
	if reserved[0].Subdomain != "myapp" {
		t.Errorf("expected subdomain 'myapp', got %s", reserved[0].Subdomain)
	}

	// Reserving again should be idempotent
	err = store.ReserveSubdomain(account.ID, "myapp")
	if err != nil {
		t.Fatalf("re-reserving same subdomain should not error: %v", err)
	}

	// Release the subdomain
	err = store.ReleaseSubdomain(account.ID, "myapp")
	if err != nil {
		t.Fatalf("failed to release subdomain: %v", err)
	}

	// Check it's gone
	owner, err = store.GetSubdomainOwner("myapp")
	if err != nil {
		t.Fatalf("failed to get owner after release: %v", err)
	}
	if owner != "" {
		t.Errorf("expected empty owner after release, got %s", owner)
	}
}

func TestSubdomainReservationLimits(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}
	defer db.Close()

	store := NewAccountStore(db)

	// Create a Pro account
	account, err := store.FindOrCreateByEmails([]string{"pro@example.com"}, "github")
	if err != nil {
		t.Fatalf("failed to create account: %v", err)
	}
	if err := store.UpdatePlan(account.ID, "pro"); err != nil {
		t.Fatalf("failed to update plan: %v", err)
	}

	// Reserve max subdomains
	for i := 0; i < MaxReservedSubdomains; i++ {
		err = store.ReserveSubdomain(account.ID, "subdomain"+string(rune('a'+i)))
		if err != nil {
			t.Fatalf("failed to reserve subdomain %d: %v", i, err)
		}
	}

	// Try to reserve one more - should fail
	err = store.ReserveSubdomain(account.ID, "toomany")
	if err == nil {
		t.Error("expected error when exceeding max reserved subdomains")
	}
}

func TestSubdomainReservationFreePlan(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}
	defer db.Close()

	store := NewAccountStore(db)

	// Create a Free account
	account, err := store.FindOrCreateByEmails([]string{"free@example.com"}, "github")
	if err != nil {
		t.Fatalf("failed to create account: %v", err)
	}

	// Free accounts cannot reserve subdomains
	err = store.ReserveSubdomain(account.ID, "myapp")
	if err == nil {
		t.Error("expected error for free plan subdomain reservation")
	}
}

func TestSubdomainReservationConflict(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}
	defer db.Close()

	store := NewAccountStore(db)

	// Create two Pro accounts
	account1, err := store.FindOrCreateByEmails([]string{"alice@example.com"}, "github")
	if err != nil {
		t.Fatalf("failed to create account1: %v", err)
	}
	if err := store.UpdatePlan(account1.ID, "pro"); err != nil {
		t.Fatalf("failed to update plan: %v", err)
	}

	account2, err := store.FindOrCreateByEmails([]string{"bob@example.com"}, "github")
	if err != nil {
		t.Fatalf("failed to create account2: %v", err)
	}
	if err := store.UpdatePlan(account2.ID, "pro"); err != nil {
		t.Fatalf("failed to update plan: %v", err)
	}

	// Alice reserves "myapp"
	err = store.ReserveSubdomain(account1.ID, "myapp")
	if err != nil {
		t.Fatalf("failed to reserve subdomain: %v", err)
	}

	// Bob tries to reserve same subdomain - should fail
	err = store.ReserveSubdomain(account2.ID, "myapp")
	if err == nil {
		t.Error("expected error when subdomain already reserved by another user")
	}
}
