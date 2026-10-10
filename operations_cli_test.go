package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
)

func TestAccountOperationsCLIAuthenticationAndDryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.db")
	configPath := filepath.Join(dir, "admins.json")
	tokenPath := filepath.Join(dir, "token")
	token := "administration-fixture-token-0123456789"
	digest := sha256.Sum256([]byte(token))
	config, err := json.Marshal([]store.AdminCredential{{Actor: "fixture-operator", TokenSHA256: hex.EncodeToString(digest[:]), Accounts: []string{"*"}}})
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{configPath: config, tokenPath: []byte(token)} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	base := []string{"--db", path, "--admin-config", configPath, "--token-file", tokenPath}
	call := func(action string, extra ...string) ([]byte, error) {
		var out bytes.Buffer
		args := append([]string{action}, base...)
		args = append(args, extra...)
		err := executeOperations(args, &out)
		return out.Bytes(), err
	}
	data, err := call("fixture-init", "--email", "owner@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	var status store.AccountStatus
	if err = json.Unmarshal(data, &status); err != nil || status.AccountID == "" || status.State != "active" {
		t.Fatal(status, err)
	}
	if _, err = call("fixture-init", "--email", "owner@example.invalid"); err == nil {
		t.Fatal("fixture init overwrote database")
	}
	if _, err = call("suspend", "--account", status.AccountID, "--expect-version", "0", "--reason", "fixture hold"); err != nil {
		t.Fatal(err)
	}
	if _, err = call("billing-bind", "--account", status.AccountID, "--provider", "fixture", "--customer", "cus_fixed", "--subscription", "sub_fixed"); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(dir, "snapshot.json")
	snap := []store.BillingSnapshot{{Provider: "fixture", CustomerID: "cus_fixed", SubscriptionID: "sub_fixed", AccountID: status.AccountID, ExpectedVersion: 0, Revision: 1, Plan: "pro"}}
	data, _ = json.Marshal(snap)
	if err = os.WriteFile(snapshotPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		data, err = call("reconcile", "--snapshots", snapshotPath)
		if err != nil {
			t.Fatal(err)
		}
		var changes []store.ReconciliationChange
		if err = json.Unmarshal(data, &changes); err != nil || changes[0].State != "change_expected" || changes[0].CurrentPlan != "free" {
			t.Fatal(changes, err)
		}
	}
	if _, err = call("reconcile", "--snapshots", snapshotPath, "--apply-fixture"); err != nil {
		t.Fatal(err)
	}
	data, err = call("status", "--account", status.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &status); err != nil || status.State != "suspended" || status.Version != 1 {
		t.Fatal(status, err)
	}
	if _, err = call("resume", "--account", status.AccountID, "--expect-version", "0", "--reason", "stale"); err == nil {
		t.Fatal("stale resume succeeded")
	}
	if _, err = call("resume", "--account", status.AccountID, "--expect-version", "1", "--reason", "review complete"); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(configPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = call("status", "--account", status.AccountID); err == nil {
		t.Fatal("public credential config accepted")
	}
	if err = os.Chmod(configPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(tokenPath, []byte("publisher-or-invalid-token-0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = call("suspend", "--account", status.AccountID, "--expect-version", "2", "--reason", "denied"); err == nil {
		t.Fatal("publisher token granted admin authority")
	}
}
