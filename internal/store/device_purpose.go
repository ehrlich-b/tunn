package store

import (
	"database/sql"
	"fmt"
)

// MigrateDevicePurpose gives outstanding codes the publisher scope.
func MigrateDevicePurpose(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(device_codes)`)
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, nn, pk int
		var name, kind string
		var def any
		if err = rows.Scan(&cid, &name, &kind, &nn, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, column := range []string{"purpose", "account_id"} {
		if !columns[column] {
			defaultValue := ""
			if column == "purpose" {
				defaultValue = "publisher"
			}
			if _, err = db.Exec(fmt.Sprintf("ALTER TABLE device_codes ADD COLUMN %s TEXT NOT NULL DEFAULT '%s'", column, defaultValue)); err != nil {
				return err
			}
		}
	}
	return nil
}
