package host

import (
	"strings"
	"testing"
)

func TestDeviceListingUsesAccountIndex(t *testing.T) {
	p := durableFixture(t)
	rows, err := p.devices.db.Query("EXPLAIN QUERY PLAN "+deviceListingQuery, "owner", "owner", "owner")
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
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan, "\n")
	if !strings.Contains(joined, "SEARCH durable_devices USING INDEX durable_devices_account (account_id=?)") || strings.Contains(joined, "SCAN durable_devices") {
		t.Fatal("device listing must search by account", joined)
	}
	t.Log(joined)
}
