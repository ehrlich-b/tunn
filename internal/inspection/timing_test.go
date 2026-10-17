package inspection

import (
	"strings"
	"testing"
)

func TestRequestTimingSplit(t *testing.T) {
	for _, test := range []struct {
		name        string
		app, tunnel int64
		slow        string
	}{{"fast", 5000, 40000, ""}, {"app", 2600000, 40000, "app"}, {"tunnel", 5000, 1200000, "tunnel"}, {"both", 1100000, 1200000, "app and tunnel"}} {
		t.Run(test.name, func(t *testing.T) {
			got := NewTiming(test.app, test.app+1000, test.app+2000, test.app+1000+test.tunnel)
			if got.OriginTTFBMS != float64(test.app)/1000 || got.TunnelTTFBMS != 2 || got.TunnelTotalMS != float64(test.tunnel)/1000 || got.SlowSide != test.slow {
				t.Fatalf("timing=%+v", got)
			}
			if test.slow != "" && !strings.Contains(got.Summary(), "slow: "+test.slow) {
				t.Fatal(got.Summary())
			}
		})
	}
	if NewTiming(0, 0, 0, 0) != nil {
		t.Fatal("unknown must not read as zero overhead")
	}
	got := NewTiming(5000, 10000, 4000, 9000)
	if got.TunnelTTFBMS != 0 || got.TunnelTotalMS != 0 {
		t.Fatalf("negative remainder: %+v", got)
	}
}

func TestRequestTimingHistoryIsolation(t *testing.T) {
	history, err := NewHistory()
	if err != nil {
		t.Fatal(err)
	}
	timing := NewTiming(10, 20, 30, 40)
	capture := history.Begin("connection", "GET", "/", nil, 0, 0)
	capture.SetTiming(timing)
	timing.OriginTotalMS = 999
	event := capture.Finish(200, "", "complete")
	if event.Timing.OriginTotalMS != .02 {
		t.Fatal("capture retained caller's pointer")
	}
	event.Timing.OriginTotalMS = 888
	first := history.Snapshot()
	first[0].Timing.OriginTotalMS = 777
	stored, ok := history.Event(event.ID)
	if !ok || stored.Timing.OriginTotalMS != .02 {
		t.Fatal("snapshot changed stored timing")
	}
}
