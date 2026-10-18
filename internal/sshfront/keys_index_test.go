package sshfront

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
)

func TestKeyListUsesAccountIndexAndPreservesMergeOwnership(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r, err := NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	accounts := store.NewAccountStore(db)
	var ids []string
	for i := 0; i < 3; i++ {
		a, err := accounts.FindOrCreateByEmails([]string{fmt.Sprintf("owner%d@example.com", i)}, "test")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, a.ID)
		if _, err := r.Add(context.Background(), a.PrimaryEmail, publicKey(t)); err != nil {
			t.Fatal(err)
		}
	}
	// Compare the actual List method with the old expression, including the
	// stored (obsolete) AccountID in each result and fingerprint ordering.
	compare := func() {
		t.Helper()
		for _, id := range ids {
			rows, err := db.Query(`SELECT fingerprint,public_key,(SELECT account_id FROM ssh_key_owners WHERE fingerprint=ssh_keys.fingerprint) FROM ssh_keys WHERE (SELECT COALESCE((SELECT account_id FROM account_merges WHERE old_id=o.account_id),o.account_id) FROM ssh_key_owners o WHERE o.fingerprint=ssh_keys.fingerprint)=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?) ORDER BY fingerprint`, id, id)
			if err != nil {
				t.Fatal(err)
			}
			want := []Key{}
			for rows.Next() {
				var key Key
				if err := rows.Scan(&key.Fingerprint, &key.PublicKey, &key.AccountID); err != nil {
					t.Fatal(err)
				}
				want = append(want, key)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.List(context.Background(), id)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("List(%s)=%v, want %v: %v", id, got, want, err)
			}
		}
	}
	compare()
	for i := 1; i < 3; i++ {
		if _, err := accounts.FindOrCreateByEmails([]string{"owner0@example.com", fmt.Sprintf("owner%d@example.com", i)}, "test"); err != nil {
			t.Fatal(err)
		}
		compare()
	}
	rows, err := db.Query("EXPLAIN QUERY PLAN "+listKeysQuery, ids[0], ids[0])
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		if detail == "SCAN k" || detail == "SCAN o" || strings.HasPrefix(detail, "SCAN k USING ") || strings.HasPrefix(detail, "SCAN o USING ") {
			t.Fatal("SSH listing scanned credentials", detail)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan, "\n")
	if !strings.Contains(joined, "SEARCH o USING COVERING INDEX ssh_key_owners_account (account_id=?)") {
		t.Fatal("SSH listing must search by account", joined)
	}
	t.Log(joined)
}
