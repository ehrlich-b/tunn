package tunn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/host"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestSDKIntegrationDomainAccountMergeAndSuspension(t *testing.T) {
	ctx := context.Background()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()
	local := storage.NewLocalStorage(db)
	owner, err := local.FindOrCreateByEmails(ctx, []string{"sdk-owner@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := local.UpdatePlan(ctx, owner.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	registry, err := domains.New(db, "sdk.test", []byte("01234567890123456789012345678901"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := registry.Add(ctx, &domainpb.Domain{Owner: owner.ID, Tunnel: "sdk-integration", Name: "sdk.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := metering.New(db, metering.WithAccountPlans(), metering.WithOwnerBudgets(1, 10))
	if err != nil {
		t.Fatal(err)
	}
	requestID := fmt.Sprintf("%032x", 1)
	if d, err := ledger.Admit(ctx, &meterpb.Event{RequestId: requestID, Owner: owner.ID, Endpoint: binding.Tunnel, Caller: "anonymous", Allowed: true}); err != nil || !d.Allowed {
		t.Fatalf("account admission: %v %v", d, err)
	}
	const publisherCredential = "sdk-account-fixture-credential"
	server := host.NewTunnelServer(&config.Config{Domain: "sdk.test"}, map[string]string{owner.PrimaryEmail: publisherCredential}, store.NewAccountStore(db), local)
	server.SetSharingBackend(ledger)
	dial, tlsConfig := startFixture(t, server.EstablishTunnel)
	o := fixtureOptions()
	o.Name, o.TLSConfig, o.Credentials.AuthToken = binding.Tunnel, tlsConfig, publisherCredential
	publish := func() *Tunnel { return startFixtureTunnel(t, ctx, o, dial, nil) }
	ready := func(tunnel *Tunnel, ownerID string) {
		t.Helper()
		deadline, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		if url, err := tunnel.WaitReady(deadline); err != nil || url != "https://"+binding.Tunnel+".sdk.test" {
			t.Fatalf("SDK readiness: %s %v", url, err)
		}
		connection, ok := server.GetTunnel(binding.Tunnel)
		if !ok || connection.AccountID != ownerID || connection.Plan != "pro" {
			t.Fatalf("SDK registration ownership: %v", connection)
		}
	}
	first := publish()
	ready(first, owner.ID)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	survivor, err := local.FindOrCreateByEmails(ctx, []string{"sdk-survivor@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := local.UpdatePlan(ctx, survivor.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if err := local.UpdatePlan(ctx, owner.ID, "free"); err != nil {
		t.Fatal(err)
	}
	merged, err := local.FindOrCreateByEmails(ctx, []string{owner.PrimaryEmail, survivor.PrimaryEmail}, "github")
	if err != nil || merged.ID != survivor.ID {
		t.Fatalf("merge: %v %v", merged, err)
	}
	listed, err := registry.List(ctx, &domainpb.Owner{Owner: survivor.ID})
	if err != nil || len(listed.Domains) != 1 || listed.Domains[0].Owner != survivor.ID || listed.Domains[0].CnameTarget != binding.CnameTarget {
		t.Fatalf("SDK domain lost across merge: %v %v", listed, err)
	}
	if d, err := ledger.Admit(ctx, &meterpb.Event{RequestId: fmt.Sprintf("%032x", 2), Owner: owner.ID, Endpoint: binding.Tunnel, Caller: "anonymous", Allowed: true}); err != nil || d.Allowed || d.Reason != "owner_request_budget" {
		t.Fatalf("SDK merge reset account cutoff: %v %v", d, err)
	}
	const adminToken = "sdk-integration-admin-fixture-0123456789"
	digest := sha256.Sum256([]byte(adminToken))
	admin, err := store.AuthenticateAdmin([]store.AdminCredential{{Actor: "sdk-fixture", TokenSHA256: fmt.Sprintf("%x", digest), Accounts: []string{survivor.ID}}}, adminToken)
	if err != nil {
		t.Fatal(err)
	}
	ops := local.OperationsStore()
	state, err := ops.Transition(ctx, admin, survivor.ID, "suspended", "SDK integration fixture", 0)
	if err != nil {
		t.Fatal(err)
	}
	rejected := publish()
	waitDone(t, rejected)
	var failure *Error
	if err := rejected.Wait(); !errors.As(err, &failure) || failure.Code != RegistrationRejected {
		t.Fatalf("SDK escaped suspension: %v", err)
	}
	if _, err := ops.Transition(ctx, admin, survivor.ID, "active", "SDK integration reviewed", state.Version); err != nil {
		t.Fatal(err)
	}
	resumed := publish()
	ready(resumed, survivor.ID)
	if err := resumed.Close(); err != nil {
		t.Fatal(err)
	}
}
