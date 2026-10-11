package storage

import (
	"testing"

	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/protobuf/proto"
)

func TestBillingLegacyAuthorityPlanFailsClosed(t *testing.T) {
	// This wire reply predates billing_state. Its cached Pro bit cannot prove
	// current paid eligibility to an upgraded replica.
	legacy, err := proto.Marshal(&internalv1.AccountResponse{Found: true, Id: "legacy", Plan: "pro", OperationalState: "active"})
	if err != nil {
		t.Fatal(err)
	}
	var reply internalv1.AccountResponse
	if err = proto.Unmarshal(legacy, &reply); err != nil {
		t.Fatal(err)
	}
	account := protoAccountToStorage(&reply)
	if account.Plan != "free" {
		t.Fatal("legacy cache conferred Pro", account)
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
