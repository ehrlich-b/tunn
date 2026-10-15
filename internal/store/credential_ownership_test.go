package store

import (
	"context"
	"testing"
)

func TestEmailRemovalBindsLegacyCredentialsBeforeMailboxReuse(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accounts := NewAccountStore(db)
	ctx := context.Background()
	owner, err := accounts.FindOrCreateByEmails([]string{"old@example.com", "new@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	// These tables model a persisted installation whose credential services have
	// not started during this process, so removal must migrate them itself.
	_, err = db.Exec(`CREATE TABLE ssh_keys(fingerprint TEXT PRIMARY KEY,public_key TEXT,owner_email TEXT);
 CREATE TABLE ssh_key_links(digest TEXT PRIMARY KEY,email TEXT);
 CREATE TABLE ssh_key_proofs(digest TEXT PRIMARY KEY,email TEXT);
 CREATE TABLE durable_devices(id TEXT PRIMARY KEY,email TEXT,account_id TEXT NOT NULL DEFAULT '');
 INSERT INTO ssh_keys VALUES('legacy','key','Old@Example.COM');
 INSERT INTO ssh_key_links VALUES('link','old@example.com');
 INSERT INTO ssh_key_proofs VALUES('proof','old@example.com');
 INSERT INTO durable_devices VALUES('device','Old@Example.COM','');
 INSERT INTO device_codes(code,user_code,email,expires_at,authorized) VALUES('legacy-code','legacy-user','Old@Example.COM',9999999999,1);`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = accounts.MutateAccountEmail(ctx, owner.ID, "new@example.com", "primary"); err != nil {
		t.Fatal(err)
	}
	if _, err = accounts.MutateAccountEmail(ctx, owner.ID, "old@example.com", "remove"); err != nil {
		t.Fatal(err)
	}
	other, err := accounts.FindOrCreateByEmails([]string{"old@example.com"}, "test")
	if err != nil || other.ID == owner.ID {
		t.Fatal(other, err)
	}
	// Restart migrations must never bind a legacy credential to the new owner.
	if err = MigrateCredentialOwnership(db); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"ssh_keys", "durable_devices", "device_codes"} {
		var id string
		if err := db.QueryRow("SELECT account_id FROM " + table).Scan(&id); err != nil || id != owner.ID {
			t.Fatal(table, id, err)
		}
	}
	for _, table := range []string{"ssh_key_links", "ssh_key_proofs"} {
		var count int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("old consent retained", table, count, err)
		}
	}
}
