package host

import (
	"testing"

	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestAccountUsageFormatting(t *testing.T) {
	for in, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 65467: "65,467", 10000000: "10,000,000"} {
		if got := formatCount(in); got != want {
			t.Errorf("formatCount(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[int64]string{10: "10 B", 10_000_000_000: "10 GB", 3_250_000_000: "3.2 GB", 500_000_000: "500 MB"} {
		if got := formatBytes(in); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", in, got, want)
		}
	}
	if percentOf(5, 0) != 0 || percentOf(50, 100) != 50 || percentOf(500, 100) != 100 {
		t.Fatal("percentOf")
	}
	rows := usageByTunnel([]*meterpb.Usage{
		{Endpoint: "b", AdmittedRequests: 2, RequestBytes: 10, ResponseBytes: 10},
		{Endpoint: "a", AdmittedRequests: 1000, RequestBytes: 30, ResponseBytes: 10},
		{Endpoint: "b", AdmittedRequests: 3, ResponseBytes: 5},
		{Endpoint: ""}, nil,
	})
	if len(rows) != 2 || rows[0].Name != "a" || rows[0].Requests != "1,000" || rows[0].Percent != 100 || rows[1].Name != "b" || rows[1].Requests != "5" || rows[1].Transfer != "25 B" || rows[1].Percent != 62 {
		t.Fatalf("%+v", rows)
	}
}
