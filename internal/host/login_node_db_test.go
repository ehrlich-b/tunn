package host

import (
	"context"
	"testing"
	"time"

	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLoginNodeAccountEmailLinkRequiresToken(t *testing.T) {
	ctx := context.Background()
	local := securityDB(t)
	account, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	server := NewLoginNodeDBServer(local)
	response, err := server.MutateAccountEmail(ctx, &internalv1.MutateAccountEmailRequest{
		AccountId: account.ID, Email: "unverified@example.com", Action: "link",
		TokenExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	if status.Code(err) != codes.InvalidArgument || response != nil {
		t.Errorf("tokenless link: response = %v, error = %v; want no response and InvalidArgument", response, err)
	}
	if linked, err := local.GetAccountByEmail(ctx, "unverified@example.com"); err != nil || linked != nil {
		t.Errorf("unverified email linked: account = %v, error = %v", linked, err)
	}
	unchanged, err := local.GetAccount(ctx, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.PrimaryEmail != account.PrimaryEmail || len(unchanged.Emails) != 1 {
		t.Errorf("account changed after tokenless link: %+v", unchanged)
	}
}
