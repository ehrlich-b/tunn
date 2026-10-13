package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"github.com/ehrlich-b/tunn/internal/common"
)

// mergeAccountAccounting runs in the inventory/email merge transaction. Combine
// overlapping counters, and preserve grant limits, rate windows and event state.
func mergeAccountAccounting(tx *sql.Tx, from, to string) error {
	if _, err := tx.Exec(`INSERT INTO account_usage(account_id,month,bytes_used)
SELECT ?,month,bytes_used FROM account_usage WHERE account_id=?
ON CONFLICT(account_id,month) DO UPDATE SET bytes_used=account_usage.bytes_used+excluded.bytes_used`, to, from); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM account_usage WHERE account_id=?", from); err != nil {
		return err
	}
	// Metering is optional; account-only stores need not initialize the ledger.
	for _, table := range []string{"meter_usage", "meter_events", "meter_grants", "web_resources", "account_provider_identities", "sharing_audit", "sharing_mutation_rate", "ip_policies", "app_devices", "app_device_invitations"} {
		var exists int
		if err := tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		if table == "ip_policies" {
			// Preserve every scope across identity merges. Conflicting defaults
			// or endpoint policies block both address families until edited.
			if _, err := tx.Exec(`INSERT INTO ip_policies(owner,endpoint,data)
SELECT ?,endpoint,data FROM ip_policies WHERE owner=?
ON CONFLICT(owner,endpoint) DO UPDATE SET data='{"deny_cidrs":["0.0.0.0/0","::/0"],"configured":true}'`, to, from); err != nil {
				return err
			}
			if _, err := tx.Exec("DELETE FROM ip_policies WHERE owner=?", from); err != nil {
				return err
			}
		} else if table == "app_devices" || table == "app_device_invitations" {
			// Keep indexed ownership and public assertion metadata canonical in
			// the verified merge transaction; the originating mailbox is retained.
			if _, err := tx.Exec("UPDATE "+table+" SET account=?,data=json_set(CAST(data AS TEXT),'$.account_id',?) WHERE account=?", to, to, from); err != nil {
				return err
			}
			if _, err := tx.Exec("UPDATE "+table+" SET data=json_set(CAST(data AS TEXT),'$.publisher',?) WHERE json_extract(CAST(data AS TEXT),'$.publisher')=?", to, from); err != nil {
				return err
			}
		} else if table == "sharing_mutation_rate" {
			if _, err := tx.Exec(`INSERT INTO sharing_mutation_rate(owner,minute,count) SELECT ?,minute,count FROM sharing_mutation_rate WHERE owner=?
   ON CONFLICT(owner) DO UPDATE SET count=CASE WHEN sharing_mutation_rate.minute=excluded.minute THEN sharing_mutation_rate.count+excluded.count WHEN excluded.minute>sharing_mutation_rate.minute THEN excluded.count ELSE sharing_mutation_rate.count END,
   minute=max(sharing_mutation_rate.minute,excluded.minute)`, to, from); err != nil {
				return err
			}
			if _, err := tx.Exec("DELETE FROM sharing_mutation_rate WHERE owner=?", from); err != nil {
				return err
			}
		} else if table == "sharing_audit" {
			if _, err := tx.Exec("UPDATE sharing_audit SET owner=? WHERE owner=?", to, from); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM sharing_audit WHERE sequence IN (SELECT sequence FROM sharing_audit WHERE owner=? ORDER BY sequence DESC LIMIT -1 OFFSET ?)`, to, common.MaxOwnerSharingAudit); err != nil {
				return err
			}
		} else if table == "account_provider_identities" {
			if _, err := tx.Exec("UPDATE account_provider_identities SET account_id=? WHERE account_id=?", to, from); err != nil {
				return err
			}
		} else if table == "web_resources" {
			if _, err := tx.Exec("UPDATE web_resources SET owner=? WHERE owner=?", to, from); err != nil {
				return err
			}
		} else if table == "meter_usage" {
			if _, err := tx.Exec(`INSERT INTO meter_usage(owner,endpoint,caller,month,requests,admitted,request_bytes,response_bytes)
SELECT ?,endpoint,caller,month,requests,admitted,request_bytes,response_bytes FROM meter_usage WHERE owner=?
ON CONFLICT(owner,endpoint,caller,month) DO UPDATE SET
requests=meter_usage.requests+excluded.requests, admitted=meter_usage.admitted+excluded.admitted,
request_bytes=meter_usage.request_bytes+excluded.request_bytes, response_bytes=meter_usage.response_bytes+excluded.response_bytes`, to, from); err != nil {
				return err
			}
			if _, err := tx.Exec("DELETE FROM meter_usage WHERE owner=?", from); err != nil {
				return err
			}
		} else {
			// Both the indexed owner and serialized protobuf JSON are authoritative.
			// table comes exclusively from the fixed list above.
			if _, err := tx.Exec("UPDATE "+table+" SET owner=?,data=json_set(CAST(data AS TEXT),'$.owner',?) WHERE owner=?", to, to, from); err != nil {
				return err
			}
		}
	}
	return mergeAppDeviceRates(tx, from, to)
}

func mergeAppDeviceRates(tx *sql.Tx, from, to string) error {
	var exists int
	if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='app_device_rates'`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	hosts := map[string]bool{}
	for _, table := range []string{"app_devices", "app_device_invitations"} {
		if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		rows, err := tx.Query(`SELECT DISTINCT json_extract(CAST(data AS TEXT),'$.hostname') FROM `+table+` WHERE account=?`, to)
		if err != nil {
			return err
		}
		for rows.Next() {
			var host string
			if err = rows.Scan(&host); err != nil {
				rows.Close()
				return err
			}
			hosts[host] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	key := func(kind, value string) string {
		d := sha256.Sum256([]byte(value))
		return kind + ":" + base64.RawURLEncoding.EncodeToString(d[:])
	}
	pairs := [][2]string{{key("invite", from), key("invite", to)}}
	for host := range hosts {
		pairs = append(pairs, [2]string{key("validate-account", from+"\x00"+host), key("validate-account", to+"\x00"+host)})
	}
	for _, pair := range pairs {
		if _, err := tx.Exec(`INSERT INTO app_device_rates(key,minute,count) SELECT ?,minute,count FROM app_device_rates WHERE key=?
 ON CONFLICT(key) DO UPDATE SET count=CASE WHEN minute=excluded.minute THEN count+excluded.count WHEN excluded.minute>minute THEN excluded.count ELSE count END,minute=max(minute,excluded.minute)`, pair[1], pair[0]); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM app_device_rates WHERE key=?`, pair[0]); err != nil {
			return err
		}
	}
	return nil
}
