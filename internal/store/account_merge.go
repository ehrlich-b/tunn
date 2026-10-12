package store

import "database/sql"

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
	for _, table := range []string{"meter_usage", "meter_events", "meter_grants", "web_resources", "account_provider_identities"} {
		var exists int
		if err := tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		if table == "account_provider_identities" {
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
	return nil
}
