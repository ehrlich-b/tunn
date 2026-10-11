package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
)

func TestR3PaymentQueueCLIAndAuditedApproval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "billing.db")
	db, err := store.OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a, err := store.NewAccountStore(db).FindOrCreateByEmails([]string{"review@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	e := store.BillingEvent{Provider: "stripe", ID: "evt_cli", Type: "checkout.session.completed", SessionID: "cs_cli", CustomerID: "cus_cli", SubscriptionID: "sub_cli", Supported: true}
	if _, err = store.NewOperationsStore(db, nil).ProcessBillingEvent(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	configPath, tokenPath := filepath.Join(dir, "admins.json"), filepath.Join(dir, "token")
	token := "administration-fixture-token-0123456789"
	digest := sha256.Sum256([]byte(token))
	credentials, _ := json.Marshal([]store.AdminCredential{{Actor: "reviewer", TokenSHA256: hex.EncodeToString(digest[:]), Accounts: []string{"*"}}})
	if err = os.WriteFile(configPath, credentials, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--db", path, "--admin-config", configPath, "--token-file", tokenPath}
	call := func(action string, extra ...string) (string, error) {
		var out bytes.Buffer
		args := append([]string{action}, base...)
		args = append(args, extra...)
		err := executeOperations(args, &out)
		return out.String(), err
	}
	data, err := call("payment-queue")
	if err != nil || !strings.Contains(data, `"session_id":"cs_cli"`) {
		t.Fatal(data, err)
	}
	var audits int
	if err = db.QueryRow(`SELECT count(*) FROM ops_payment_review_audit`).Scan(&audits); err != nil || audits != 0 {
		t.Fatal("queue mutated DB", audits, err)
	}
	decision := store.PaymentReview{Provider: e.Provider, SubscriptionID: e.SubscriptionID, CustomerID: e.CustomerID, SessionID: e.SessionID, EventID: e.ID, AccountID: a.ID, Action: "approve", Reason: "verified first purchase", ProviderReadAt: time.Now(), EvidenceSHA256: strings.Repeat("a", 64)}
	input := filepath.Join(dir, "decision.json")
	body, _ := json.Marshal(decision)
	if err = os.WriteFile(input, body, 0600); err != nil {
		t.Fatal(err)
	}
	if data, err = call("payment-review", "--snapshots", input); err != nil {
		t.Fatal(data, err)
	}
	if _, err = call("payment-review", "--snapshots", input); !strings.Contains(errString(err), "version conflict") {
		t.Fatal("stale approval accepted", err)
	}
	if data, err = call("payment-queue"); err != nil || strings.TrimSpace(data) != "[]" {
		t.Fatal(data, err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM ops_payment_review_audit WHERE actor='reviewer' AND action='approve'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal(audits, err)
	}
	if got, err := store.NewAccountStore(db).GetByID(a.ID); err != nil || got.Plan != "free" {
		t.Fatal("approval invented a verified grant", got, err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
