package store

import (
	"database/sql"
	"encoding/json"
)

// Transfer counters with the verified email bucket: merging identities must
// never reset bandwidth or request allowances.
func mergeAccountUsage(tx *sql.Tx, primary, previous string) error {
	if _, err := tx.Exec(`INSERT INTO account_usage(account_id,month,bytes_used)
 SELECT ?,month,bytes_used FROM account_usage WHERE account_id=?
 ON CONFLICT(account_id,month) DO UPDATE SET bytes_used=account_usage.bytes_used+excluded.bytes_used`, primary, previous); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM account_usage WHERE account_id=?`, previous); err != nil {
		return err
	}
	var exists int
	if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meter_usage'`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	if _, err := tx.Exec(`INSERT INTO meter_usage(owner,endpoint,caller,month,requests,admitted,request_bytes,response_bytes)
 SELECT ?,endpoint,caller,month,requests,admitted,request_bytes,response_bytes FROM meter_usage WHERE owner=?
 ON CONFLICT(owner,endpoint,caller,month) DO UPDATE SET requests=meter_usage.requests+excluded.requests,admitted=meter_usage.admitted+excluded.admitted,request_bytes=meter_usage.request_bytes+excluded.request_bytes,response_bytes=meter_usage.response_bytes+excluded.response_bytes`, primary, previous); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM meter_usage WHERE owner=?`, previous); err != nil {
		return err
	}
	for _, table := range []string{"meter_events", "meter_grants"} {
		rows, err := tx.Query(`SELECT id,data FROM `+table+` WHERE owner=?`, previous)
		if err != nil {
			return err
		}
		type entry struct {
			id   string
			data []byte
		}
		var entries []entry
		for rows.Next() {
			var e entry
			if err := rows.Scan(&e.id, &e.data); err != nil {
				_ = rows.Close()
				return err
			}
			entries = append(entries, e)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return err
		}
		for _, e := range entries {
			var v map[string]json.RawMessage
			if err := json.Unmarshal(e.data, &v); err != nil {
				return err
			}
			v["owner"], err = json.Marshal(primary)
			if err != nil {
				return err
			}
			data, err := json.Marshal(v)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE `+table+` SET owner=?,data=? WHERE id=?`, primary, data, e.id); err != nil {
				return err
			}
		}
	}
	return nil
}
