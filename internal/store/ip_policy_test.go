package store

import (
	"encoding/json"
	"testing"

	"github.com/ehrlich-b/tunn/internal/ippolicy"
)

func TestIPPolicyAccountMergePreservesAndBlocksConflicts(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accounts := NewAccountStore(db)
	a, err := accounts.FindOrCreateByEmails([]string{"ip-a@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	b, err := accounts.FindOrCreateByEmails([]string{"ip-b@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE ip_policies(owner TEXT NOT NULL, endpoint TEXT NOT NULL,data BLOB NOT NULL,PRIMARY KEY(owner,endpoint));`)
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{a.ID, b.ID} {
		if _, err = db.Exec(`INSERT INTO ip_policies VALUES(?,'','{"allow_cidrs":["192.0.2.0/24"],"configured":true}')`, owner); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(`INSERT INTO ip_policies VALUES(?,'api','{"allow_cidrs":["2001:db8::/32"],"configured":true}')`, b.ID); err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{"ip-a@example.invalid", "ip-b@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	if err = db.QueryRow(`SELECT data FROM ip_policies WHERE owner=? AND endpoint=''`, merged.ID).Scan(&data); err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Allow []string `json:"allow_cidrs"`
		Deny  []string `json:"deny_cidrs"`
	}
	if err = json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []string{"192.0.2.1", "2001:db8::1"} {
		if ippolicy.Allowed(peer, policy.Allow, policy.Deny) {
			t.Fatal("merge loosened conflicting default")
		}
	}
	if err = db.QueryRow(`SELECT data FROM ip_policies WHERE owner=? AND endpoint='api'`, merged.ID).Scan(&data); err != nil {
		t.Fatal(err)
	}
	policy.Allow = nil
	policy.Deny = nil
	if err = json.Unmarshal(data, &policy); err != nil || !ippolicy.Allowed("2001:db8::1", policy.Allow, policy.Deny) {
		t.Fatal("merge lost unique endpoint", err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM ip_policies WHERE owner<>?`, merged.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("stale owner rows", count, err)
	}
}
