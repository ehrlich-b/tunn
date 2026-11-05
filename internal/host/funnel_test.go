package host

import (
	"context"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
)

func TestFunnelLedger(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	account, err := store.NewAccountStore(db).FindOrCreateByEmails([]string{"person@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"signup", "tunnel", "mcp_consent", "checkout_start", "checkout_completed", "pro_active"} {
		t.Run(stage, func(t *testing.T) {
			for i := 0; i < 2; i++ {
				store.RecordFunnel(context.Background(), db, stage, account.ID)
			}
			var count int
			var gotStage, hash, stamp string
			if err := db.QueryRow(`SELECT count(*),stage,account_hash,occurred_at FROM funnel_events WHERE stage=?`, stage).Scan(&count, &gotStage, &hash, &stamp); err != nil {
				t.Fatal(err)
			}
			if count != 1 || gotStage != stage || len(hash) != 64 || stamp == "" || strings.Contains(gotStage+hash+stamp, "person@example.com") {
				t.Fatalf("unexpected ledger row: %d %q %q %q", count, gotStage, hash, stamp)
			}
		})
	}
}
