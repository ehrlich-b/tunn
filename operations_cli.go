package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
)

const operationsUsage = `tunn admin <action> --db PATH --admin-config PATH --token-file PATH
Actions: status, suspend, resume, billing-bind, billing-status, billing-events, reconcile,
         report-intake, report-respond, fixture-init, migrate, reconcile-legacy
Account operations: --account UUID --expect-version N --reason TEXT
Billing bind: --account UUID --provider NAME --customer ID --subscription ID
Billing fixtures: --events PATH (disposable fixture databases only)
Reconcile: --snapshots PATH [--apply-fixture | --apply-reviewed] (default: read-only dry run)
Reviewed apply requires fresh Stripe evidence and receipts; see GO-LIVE.md.
Legacy reconciliation: --snapshots PATH (explicit decisions; requires accounts:["*"])
Reports: --account UUID --category abuse|billing|availability --endpoint NAME
Response: --report ID --response triaged|action_taken|closed --expect-version N
Fixture init: --email fixture@example.invalid (creates a new disposable database)
Credentials: owner-only JSON [{"actor":"operator","token_sha256":"HEX","accounts":["UUID"]}]
No network, provider writes, mail, or public administration endpoint.
`

func readBoundedJSON(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return fmt.Errorf("input must be a regular file of at most 1 MiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("expected one JSON value")
	}
	return nil
}
func privateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return nil, fmt.Errorf("credential file must be a regular owner-only file of at most 64 KiB")
	}
	return os.ReadFile(path)
}
func adminPrincipal(configPath, tokenPath string) (store.AdminPrincipal, error) {
	data, err := privateFile(configPath)
	if err != nil {
		return store.AdminPrincipal{}, err
	}
	var credentials []store.AdminCredential
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&credentials); err != nil {
		return store.AdminPrincipal{}, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || len(credentials) > 128 {
		return store.AdminPrincipal{}, fmt.Errorf("invalid administration config")
	}
	token, err := privateFile(tokenPath)
	if err != nil {
		return store.AdminPrincipal{}, err
	}
	return store.AuthenticateAdmin(credentials, strings.TrimSpace(string(token)))
}
func runOperations(args []string) {
	if err := executeOperations(args, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(os.Stdout, operationsUsage)
			return
		}
		_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"state": "error", "error": err.Error()})
		os.Exit(1)
	}
}
func executeOperations(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("administration action required")
	}
	if args[0] == "--help" || args[0] == "-h" {
		return flag.ErrHelp
	}
	action := args[0]
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var dbPath, configPath, tokenPath, account, reason, provider, customer, subscription, input, email, category, endpoint, report, response string
	var expected int64
	var apply, applyReviewed bool
	fs.StringVar(&dbPath, "db", "", "explicit local database path")
	fs.StringVar(&configPath, "admin-config", "", "operator-owned configuration")
	fs.StringVar(&tokenPath, "token-file", "", "administration token")
	fs.StringVar(&account, "account", "", "account UUID")
	fs.StringVar(&reason, "reason", "", "bounded operational reason")
	fs.Int64Var(&expected, "expect-version", -1, "compare-and-swap version")
	fs.StringVar(&provider, "provider", "stripe", "provider adapter name")
	fs.StringVar(&customer, "customer", "", "customer ID")
	fs.StringVar(&subscription, "subscription", "", "subscription ID")
	fs.StringVar(&input, "snapshots", "", "supplied provider snapshots")
	fs.StringVar(&input, "events", "", "supplied fixture events")
	fs.BoolVar(&apply, "apply-fixture", false, "apply only to a disposable local fixture database")
	fs.BoolVar(&applyReviewed, "apply-reviewed", false, "commit explicitly reviewed Stripe snapshots to the local database")
	fs.StringVar(&email, "email", "", "fixture account email")
	fs.StringVar(&category, "category", "", "report category")
	fs.StringVar(&endpoint, "endpoint", "", "report endpoint")
	fs.StringVar(&report, "report", "", "report ID")
	fs.StringVar(&response, "response", "", "report response state")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional argument")
	}
	valid := map[string]bool{"status": true, "suspend": true, "resume": true, "billing-bind": true, "billing-events": true, "reconcile": true, "report-intake": true, "report-respond": true, "fixture-init": true, "migrate": true}
	valid["billing-status"] = true
	valid["reconcile-legacy"] = true
	if !valid[action] || dbPath == "" || configPath == "" || tokenPath == "" {
		return fmt.Errorf("require an action, explicit database and administration credentials")
	}
	if (apply || applyReviewed) && action != "reconcile" || apply && applyReviewed {
		return fmt.Errorf("select one apply mode, only with reconcile")
	}
	principal, err := adminPrincipal(configPath, tokenPath)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var db *sql.DB
	if action == "fixture-init" {
		if !strings.HasSuffix(email, "@example.invalid") {
			return fmt.Errorf("fixture email must end in @example.invalid")
		}
		file, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if err = file.Close(); err != nil {
			return err
		}
		db, err = store.OpenLocal(abs)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		if _, err = db.Exec(`CREATE TABLE ops_fixture(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL); INSERT INTO ops_fixture VALUES(1,'disposable-local');`); err != nil {
			return err
		}
		acc, err := store.NewAccountStore(db).FindOrCreateByEmails([]string{email}, "fixture")
		if err != nil {
			return err
		}
		status, err := store.NewOperationsStore(db, nil).AdminStatus(ctx, principal, acc.ID)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(status)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("database must be an existing regular file")
	}
	dbMode := "rw"
	if action == "status" || action == "billing-status" || action == "reconcile" && !apply && !applyReviewed {
		dbMode = "ro"
	}
	dsn := (&url.URL{Scheme: "file", Path: abs, RawQuery: "mode=" + dbMode}).String()
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(ctx, "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;"); err != nil {
		return err
	}
	ops := store.NewOperationsStore(db, nil)
	var result any
	switch action {
	case "reconcile-legacy":
		var decisions []store.LegacyEntitlementDecision
		if err = readBoundedJSON(input, &decisions); err != nil {
			return err
		}
		err = ops.ReconcileLegacyEntitlements(ctx, principal, decisions)
		result = map[string]string{"state": "legacy_entitlements_reconciled"}
	case "migrate":
		err = ops.AdminMigrate(ctx, principal, account)
		result = map[string]string{"state": "migrated"}
	case "status":
		result, err = ops.AdminStatus(ctx, principal, account)
	case "suspend", "resume":
		state := "suspended"
		if action == "resume" {
			state = "active"
		}
		result, err = ops.Transition(ctx, principal, account, state, reason, expected)
	case "billing-bind":
		err = ops.BindBilling(ctx, principal, store.BillingMapping{Provider: provider, CustomerID: customer, SubscriptionID: subscription, AccountID: account})
		result = map[string]string{"state": "bound", "account_id": account}
	case "billing-status":
		result, err = ops.AdminBillingStatus(ctx, principal, provider, subscription)
	case "billing-events":
		var marker string
		if err = db.QueryRowContext(ctx, "SELECT value FROM ops_fixture WHERE id=1").Scan(&marker); err != nil || marker != "disposable-local" {
			return fmt.Errorf("events command requires a disposable local fixture")
		}
		var events []store.BillingEvent
		if err = readBoundedJSON(input, &events); err != nil {
			return err
		}
		if len(events) == 0 || len(events) > 1000 {
			return fmt.Errorf("require 1..1000 fixture events")
		}
		results := []*store.BillingResult{}
		for _, event := range events {
			// Fixture replay requires a principal authorized for the bound account.
			var owner string
			if err = db.QueryRowContext(ctx, "SELECT account_id FROM ops_billing_mappings WHERE provider=? AND subscription_id=?", event.Provider, event.SubscriptionID).Scan(&owner); err != nil {
				return err
			}
			if _, err = ops.AdminStatus(ctx, principal, owner); err != nil {
				return err
			}
			item, processErr := ops.ProcessBillingEvent(ctx, event)
			if processErr != nil {
				return processErr
			}
			results = append(results, item)
		}
		result = results
	case "reconcile":
		var snapshots []store.BillingSnapshot
		if err = readBoundedJSON(input, &snapshots); err != nil {
			return err
		}
		if applyReviewed {
			result, err = ops.ApplyReviewedBilling(ctx, principal, snapshots)
		} else {
			result, err = ops.Reconcile(ctx, principal, snapshots, apply)
		}
	case "report-intake":
		if _, err = ops.AdminStatus(ctx, principal, account); err != nil {
			return err
		}
		result, err = ops.IntakeReport(ctx, account, category, endpoint)
	case "report-respond":
		result, err = ops.RespondReport(ctx, principal, report, response, expected)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
