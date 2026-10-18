package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialAccountIndexesMigration(t *testing.T) {
	for _, version := range []string{"fresh", "previous", "legacy"} {
		t.Run(version, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials.db")
			db, err := OpenLocal(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { db.Close() }()
			account, err := NewAccountStore(db).FindOrCreateByEmails([]string{"owner@example.com"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			// Credential tables are created lazily by their services. Migration
			// must also succeed before either service has initialized its tables.
			if err := MigrateCredentialOwnership(db); err != nil {
				t.Fatal(err)
			}
			deviceSchema := `CREATE TABLE durable_devices (
 id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL,
 digest BLOB NOT NULL UNIQUE, created INTEGER NOT NULL, last_used INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0, purpose TEXT NOT NULL DEFAULT 'publisher'`
			if version != "legacy" {
				deviceSchema += `, account_id TEXT NOT NULL DEFAULT ''`
			}
			if _, err := db.Exec(deviceSchema + `);
 CREATE INDEX durable_devices_email ON durable_devices(email);
 CREATE TABLE ssh_keys(fingerprint TEXT PRIMARY KEY, public_key TEXT NOT NULL, owner_email TEXT NOT NULL);`); err != nil {
				t.Fatal(err)
			}
			if version == "previous" {
				// The previous release has durable ownership but neither account index.
				if _, err := db.Exec(`CREATE TABLE ssh_key_owners(fingerprint TEXT PRIMARY KEY, account_id TEXT NOT NULL);
 INSERT INTO ssh_key_owners VALUES('key',?);
 INSERT INTO durable_devices VALUES('device','owner@example.com','laptop',x'01',10,20,30,'management',?)`, account.ID, account.ID); err != nil {
					t.Fatal(err)
				}
			} else if version == "legacy" {
				if _, err := db.Exec(`INSERT INTO durable_devices VALUES('device','owner@example.com','laptop',x'01',10,20,30,'management')`); err != nil {
					t.Fatal(err)
				}
			}
			if version != "fresh" {
				if _, err := db.Exec(`INSERT INTO ssh_keys VALUES('key','public key','owner@example.com')`); err != nil {
					t.Fatal(err)
				}
				// Persist the old database and migrate on a new connection.
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				db, err = OpenLocal(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				if err := MigrateCredentialOwnership(db); err != nil {
					t.Fatal(err)
				}
			}
			for index, want := range map[string]string{
				"durable_devices_account": "account_id",
				"ssh_key_owners_account":  "account_id,fingerprint",
			} {
				rows, err := db.Query(`SELECT name FROM pragma_index_info(?) ORDER BY seqno`, index)
				if err != nil {
					t.Fatal(err)
				}
				var columns []string
				for rows.Next() {
					var column string
					if err := rows.Scan(&column); err != nil {
						t.Fatal(err)
					}
					columns = append(columns, column)
				}
				err = rows.Err()
				rows.Close()
				if err != nil || strings.Join(columns, ",") != want {
					t.Fatalf("index %s columns=%v, want %s: %v", index, columns, want, err)
				}
			}
			if version != "fresh" {
				var owner, name, purpose string
				var created, used, revoked int
				var digest []byte
				if err := db.QueryRow(`SELECT account_id,name,digest,created,last_used,revoked,purpose FROM durable_devices WHERE id='device'`).Scan(&owner, &name, &digest, &created, &used, &revoked, &purpose); err != nil {
					t.Fatal(err)
				}
				if owner != account.ID || name != "laptop" || string(digest) != "\x01" || created != 10 || used != 20 || revoked != 30 || purpose != "management" {
					t.Fatal("migration changed credential data", owner, name, digest, created, used, revoked, purpose)
				}
				if err := db.QueryRow(`SELECT account_id FROM ssh_key_owners WHERE fingerprint='key'`).Scan(&owner); err != nil || owner != account.ID {
					t.Fatal("migration changed SSH ownership", owner, err)
				}
			}
			// New indexes must survive restart and remain non-unique: an account
			// can own many credentials, including rollback's three-column inserts.
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO ssh_keys VALUES('new1','public1','owner@example.com'),('new2','public2','owner@example.com');
 INSERT INTO durable_devices VALUES('new1','owner@example.com','one',x'02',1,1,0,'publisher',?),('new2','owner@example.com','two',x'03',1,1,0,'publisher',?)`, account.ID, account.ID); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := db.QueryRow(`SELECT count(*) FROM ssh_key_owners WHERE fingerprint IN ('new1','new2') AND account_id=?`, account.ID).Scan(&count); err != nil || count != 2 {
				t.Fatal("rollback inserts lost ownership", count, err)
			}
			t.Log("account indexes survive repeated migration and restart; credential data and rollback inserts preserved")
		})
	}
}
