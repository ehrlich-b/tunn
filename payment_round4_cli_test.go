package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
)

func TestR4BillingStatusPaginationCLI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "billing.db")
	db, err := store.OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a, err := store.NewAccountStore(db).FindOrCreateByEmails([]string{"pagination@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 101; i++ {
		sub := fmt.Sprintf("sub_cli_%03d", i)
		if _, err = db.Exec(`INSERT INTO ops_checkout_payments(provider,subscription_id,customer_id,outcome,event_id,account_id) VALUES('stripe',?,?,'duplicate_payment_refund_needed',?,?)`, sub, "cus_"+sub, "evt_"+sub, a.ID); err != nil {
			t.Fatal(err)
		}
	}
	configPath, tokenPath := filepath.Join(dir, "admins.json"), filepath.Join(dir, "token")
	token := "administration-fixture-token-0123456789"
	digest := sha256.Sum256([]byte(token))
	credentials, err := json.Marshal([]store.AdminCredential{{Actor: "reviewer", TokenSHA256: hex.EncodeToString(digest[:]), Accounts: []string{a.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, credentials, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(after string) store.BillingStatus {
		t.Helper()
		var out bytes.Buffer
		if err := executeOperations([]string{"billing-status", "--db", path, "--admin-config", configPath, "--token-file", tokenPath, "--subscription", "sub_cli_100", "--after", after}, &out); err != nil {
			t.Fatal(err)
		}
		var status store.BillingStatus
		if err := json.Unmarshal(out.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	first := call("")
	if first.PaymentsNext != "stripe/sub_cli_099" || len(first.Payments) != 101 || first.Payments[100].SubscriptionID != "sub_cli_100" {
		t.Fatal("CLI omitted target or continuation", first)
	}
	last := call(first.PaymentsNext)
	if last.PaymentsNext != "" || len(last.Payments) != 1 || last.Payments[0].SubscriptionID != "sub_cli_100" {
		t.Fatal("CLI continuation failed", last)
	}
	var changed int
	if err = db.QueryRow(`SELECT count(*) FROM ops_checkout_payments WHERE version!=0 OR resolution!=''`).Scan(&changed); err != nil || changed != 0 {
		t.Fatal("status changed payment evidence", changed, err)
	}
}
