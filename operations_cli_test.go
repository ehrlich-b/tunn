package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestBillingLegacyReconciliationCLIRequiresGlobalCredential(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "legacy.db")
	data, err := os.ReadFile("internal/store/testdata/legacy110485c.sql")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(string(data)); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.OpenLocal(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var id string
	if err = db.QueryRow(`SELECT id FROM accounts WHERE primary_email='manual@example.invalid'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	token := "legacy-cli-review-token-0123456789abcdef"
	digest := sha256.Sum256([]byte(token))
	configPath, tokenPath, input := filepath.Join(dir, "admins.json"), filepath.Join(dir, "token"), filepath.Join(dir, "decisions.json")
	decisions, _ := json.Marshal([]store.LegacyEntitlementDecision{{OriginalAccountID: id, AccountID: id, Plan: "free", Reason: "explicit global CLI review"}})
	if err = os.WriteFile(input, decisions, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{id, "*"} {
		config, _ := json.Marshal([]store.AdminCredential{{Actor: "global-reviewer", TokenSHA256: hex.EncodeToString(digest[:]), Accounts: []string{scope}}})
		if err = os.WriteFile(configPath, config, 0600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err = executeOperations([]string{"reconcile-legacy", "--db", dbPath, "--admin-config", configPath, "--token-file", tokenPath, "--snapshots", input}, &out)
		if scope != "*" && !errors.Is(err, store.ErrDenied) || scope == "*" && (err != nil || !strings.Contains(out.String(), "legacy_entitlements_reconciled")) {
			t.Fatal(scope, out.String(), err)
		}
	}
	var actor string
	if err = db.QueryRow(`SELECT actor FROM ops_legacy_entitlement_audit`).Scan(&actor); err != nil || actor != "global-reviewer" {
		t.Fatal(actor, err)
	}
}

func TestReviewedBillingCLIOnNonFixtureDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "local.db")
	db, err := store.OpenLocal(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	account, err := store.NewAccountStore(db).FindOrCreateByEmails([]string{"billing-cli@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	token := "reviewed-billing-cli-token-0123456789"
	digest := sha256.Sum256([]byte(token))
	config, _ := json.Marshal([]store.AdminCredential{{Actor: "reviewer", TokenSHA256: hex.EncodeToString(digest[:]), Accounts: []string{account.ID}}})
	configPath, tokenPath := filepath.Join(dir, "admins.json"), filepath.Join(dir, "token")
	for path, data := range map[string][]byte{configPath: config, tokenPath: []byte(token)} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	call := func(action string, extra ...string) ([]byte, error) {
		var out bytes.Buffer
		args := []string{action, "--db", dbPath, "--admin-config", configPath, "--token-file", tokenPath}
		args = append(args, extra...)
		err := executeOperations(args, &out)
		return out.Bytes(), err
	}
	if _, err = call("billing-bind", "--account", account.ID, "--customer", "cus_cli", "--subscription", "sub_cli"); err != nil {
		t.Fatal(err)
	}
	ops := store.NewOperationsStore(db, nil)
	if _, err = ops.ProcessBillingEvent(context.Background(), store.BillingEvent{Provider: "stripe", ID: "evt_cli", Type: "checkout.session.completed", CustomerID: "cus_cli", SubscriptionID: "sub_cli", Supported: true}); err != nil {
		t.Fatal(err)
	}
	data, err := call("billing-status", "--subscription", "sub_cli")
	var status store.BillingStatus
	if err != nil || json.Unmarshal(data, &status) != nil || status.Mapping == nil || status.Mapping.Version != 0 || len(status.PendingEventIDs) != 1 {
		t.Fatal(string(data), err)
	}
	snapshots := []store.BillingSnapshot{{Provider: "stripe", CustomerID: "cus_cli", SubscriptionID: "sub_cli", AccountID: account.ID, Plan: "pro", EventIDs: status.PendingEventIDs, ProviderReadAt: time.Now(), EvidenceSHA256: strings.Repeat("c", 64), PriceID: "price_reviewed", ProviderStatus: "active", PaymentConfirmed: true}}
	snapshotPath := filepath.Join(dir, "snapshot.json")
	data, _ = json.Marshal(snapshots)
	if err = os.WriteFile(snapshotPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if data, err = call("reconcile", "--snapshots", snapshotPath); err != nil || !bytes.Contains(data, []byte(`"state":"change_expected"`)) {
		t.Fatal(string(data), err)
	}
	var plan string
	if err = db.QueryRow("SELECT plan FROM accounts WHERE id=?", account.ID).Scan(&plan); err != nil || plan != "free" {
		t.Fatal("dry run changed plan", plan, err)
	}
	for _, args := range [][]string{{"--apply-fixture"}, {"--apply-fixture", "--apply-reviewed"}} {
		if _, err = call("reconcile", append([]string{"--snapshots", snapshotPath}, args...)...); err == nil {
			t.Fatal("invalid apply mode accepted", args)
		}
	}
	if data, err = call("reconcile", "--snapshots", snapshotPath, "--apply-reviewed"); err != nil || !bytes.Contains(data, []byte(`"state":"applied"`)) {
		t.Fatal(string(data), err)
	}
	if err = db.QueryRow("SELECT plan FROM accounts WHERE id=?", account.ID).Scan(&plan); err != nil || plan != "pro" {
		t.Fatal(plan, err)
	}
	if _, err = call("reconcile", "--snapshots", snapshotPath, "--apply-reviewed"); err == nil {
		t.Fatal("stale review applied")
	}
}

func TestFunnelSourceCLIReadOnlyAndScope(t *testing.T) {
	dir := t.TempDir()
	path, configPath, tokenPath := filepath.Join(dir, "funnel.db"), filepath.Join(dir, "admins.json"), filepath.Join(dir, "token")
	token := "funnel-operator-token-0123456789abcdef"
	digest := sha256.Sum256([]byte(token))
	writeConfig := func(accounts []string) {
		t.Helper()
		data, err := json.Marshal([]store.AdminCredential{{Actor: "funnel-operator", TokenSHA256: hex.EncodeToString(digest[:]), Accounts: accounts}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig([]string{"*"})
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(action string, extra ...string) ([]byte, error) {
		var out bytes.Buffer
		args := []string{action, "--db", path, "--admin-config", configPath, "--token-file", tokenPath}
		err := executeOperations(append(args, extra...), &out)
		return out.Bytes(), err
	}
	if _, err := call("fixture-init", "--email", "funnel@example.invalid"); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/funnel_sources.json")
	if err != nil {
		t.Fatal(err)
	}
	var want []store.FunnelSourceDay
	if err = json.Unmarshal(fixture, &want); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the fixture-init signup for the first expected event.
	if _, err = db.Exec(`UPDATE funnel_events SET occurred_at=?,source=? WHERE stage='signup'`, want[0].Day+"T12:00:00Z", want[0].Source); err != nil {
		t.Fatal(err)
	}
	for i, row := range want {
		start := 0
		if i == 0 {
			start = 1
		}
		for j := start; j < row.Count; j++ {
			hash := sha256.Sum256([]byte(fmt.Sprintf("fixture-%d-%d", i, j)))
			if _, err = db.Exec(`INSERT INTO funnel_events(stage,account_hash,occurred_at,source) VALUES('signup',?,?,?)`, hex.EncodeToString(hash[:]), row.Day+"T12:00:00Z", row.Source); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		data, err := call("funnel", "--json")
		if err != nil {
			t.Fatal(err)
		}
		var report store.FunnelReport
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(report.SignupSources, want) || !reflect.DeepEqual(report.Days, []store.FunnelDay{{Day: "2026-10-23", Stage: "signup", Count: 4}, {Day: "2026-10-24", Stage: "signup", Count: 5}}) || report.CheckoutWithoutPro != 0 {
			t.Fatalf("report=%+v", report)
		}
		data, err = call("funnel")
		if err != nil || !strings.Contains(string(data), "DAY\tSTAGE\tCOUNT") || !strings.Contains(string(data), "\tsignup\t4") || strings.Contains(string(data), "funnel@example.invalid") {
			t.Fatalf("table=%s err=%v", data, err)
		}
		if !strings.Contains(string(data), "DAY\tSIGNUP SOURCE\tCOUNT") {
			t.Fatal("missing signup source table", string(data))
		}
		for _, row := range want {
			if !strings.Contains(string(data), fmt.Sprintf("%s\t%s\t%d\n", row.Day, row.Source, row.Count)) {
				t.Fatalf("missing source row %+v: %s", row, data)
			}
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("read changed database: %v", err)
	}
	writeConfig([]string{"another-account"})
	if _, err := call("funnel", "--json"); !errors.Is(err, store.ErrDenied) {
		t.Fatalf("scoped operator read global funnel: %v", err)
	}
}
