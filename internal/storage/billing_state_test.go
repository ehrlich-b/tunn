package storage

import (
	"testing"

	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/protobuf/proto"
)

func TestBillingLegacyAuthorityPreservesGrant(t *testing.T) {
	// This wire reply predates billing_state. Preserve the existing authority
	// entitlement during a schema-only rolling upgrade.
	legacy, err := proto.Marshal(&internalv1.AccountResponse{Found: true, Id: "legacy", Plan: "pro", OperationalState: "active"})
	if err != nil {
		t.Fatal(err)
	}
	var reply internalv1.AccountResponse
	if err = proto.Unmarshal(legacy, &reply); err != nil {
		t.Fatal(err)
	}
	account := protoAccountToStorage(&reply)
	if account.Plan != "pro" {
		t.Fatal("legacy authority grant lost during rolling upgrade", account)
	}
	reply.BillingState = "active"
	if account = protoAccountToStorage(&reply); account.Plan != "pro" {
		t.Fatal("verified authority state lost", account)
	}
	reply.BillingState = "support"
	if account = protoAccountToStorage(&reply); account.Plan != "free" {
		t.Fatal("inactive authority state conferred Pro", account)
	}
}
