package metering

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/protobuf/proto"
)

func TestLedgerSeededAccountingStateMachine(t *testing.T) {
	for _, seed := range []int64{7, 91, 20261010} {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			s, _ := fixture(t)
			s.ownerRequests, s.ownerBytes = 9, 37
			now := time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC)
			s.now = func() time.Time { return now }
			rng := rand.New(rand.NewSource(seed))
			type request struct {
				input                       *pb.Event
				admission                   *pb.Decision
				month                       string
				requestBytes, responseBytes int64
				finished                    bool
			}
			var requests []*request
			totals := map[string]*pb.Usage{}
			for step := 0; step < 160; step++ {
				if step == 80 {
					now = now.Add(time.Second)
				}
				month := now.UTC().Format("2006-01")
				if totals[month] == nil {
					totals[month] = &pb.Usage{}
				}
				op := rng.Intn(4)
				if len(requests) == 0 || op == 0 {
					e := event(nil, len(requests)+1)
					e.Endpoint = fmt.Sprintf("api-%d", rng.Intn(3))
					e.Caller = fmt.Sprintf("caller-%d", rng.Intn(2))
					e.ContentLength = int64(rng.Intn(6))
					u := totals[month]
					available := s.ownerBytes - u.RequestBytes - u.ResponseBytes
					wantAllowed := u.AdmittedRequests < s.ownerRequests && available > 0 && e.ContentLength <= available
					d := admit(t, s, e)
					if d.Allowed != wantAllowed || d.BytesRemaining != available {
						t.Fatalf("seed=%d step=%d admission=%v expected allowed=%t bytes=%d", seed, step, d, wantAllowed, available)
					}
					u.Requests++
					if wantAllowed {
						u.AdmittedRequests++
					}
					if d.RequestsRemaining != max(0, s.ownerRequests-u.AdmittedRequests) {
						t.Fatalf("step=%d remaining requests=%d totals=%v", step, d.RequestsRemaining, u)
					}
					requests = append(requests, &request{input: e, admission: proto.Clone(d).(*pb.Decision), month: month, finished: !d.Allowed})
					continue
				}
				r := requests[rng.Intn(len(requests))]
				u := totals[r.month]
				if op == 1 {
					d := admit(t, s, r.input)
					if !proto.Equal(d, r.admission) {
						t.Fatalf("step=%d replay changed immutable admission: got %v want %v", step, d, r.admission)
					}
				} else if !r.finished && op == 2 {
					reqDelta, respDelta := int64(rng.Intn(8)), int64(rng.Intn(8))
					available := s.ownerBytes - u.RequestBytes - u.ResponseBytes
					acceptedReq := min(reqDelta, available)
					acceptedResp := min(respDelta, available-acceptedReq)
					d := charge(t, s, r.input.RequestId, r.requestBytes+reqDelta, r.responseBytes+respDelta)
					r.requestBytes += acceptedReq
					r.responseBytes += acceptedResp
					u.RequestBytes += acceptedReq
					u.ResponseBytes += acceptedResp
					if d.RequestBytes != r.requestBytes || d.ResponseBytes != r.responseBytes || d.Allowed != (reqDelta+respDelta <= available) || d.BytesRemaining != available-acceptedReq-acceptedResp {
						t.Fatalf("seed=%d step=%d charge=%v model request=%d response=%d available=%d", seed, step, d, r.requestBytes, r.responseBytes, available)
					}
				} else if !r.finished && op == 3 {
					actual := int64(rng.Intn(int(r.responseBytes) + 1))
					finish(t, s, r.input, actual)
					u.ResponseBytes -= r.responseBytes - actual
					r.responseBytes, r.finished = actual, true
					finish(t, s, r.input, actual) // retries cannot refund twice
				}
			}
			admissionMonths := map[string]string{}
			for _, r := range requests {
				admissionMonths[r.input.RequestId] = r.month
			}
			for month, want := range totals {
				out, err := s.Export(context.Background(), &pb.ExportRequest{Owner: "owner@example.com", Month: month})
				if err != nil {
					t.Fatal(err)
				}
				got := out.OwnerUsage
				if got.Requests != want.Requests || got.AdmittedRequests != want.AdmittedRequests || got.RequestBytes != want.RequestBytes || got.ResponseBytes != want.ResponseBytes || got.TotalBytes != want.RequestBytes+want.ResponseBytes || out.AuditTruncated || out.UsageTruncated {
					t.Fatalf("seed=%d month=%s totals=%v want=%v", seed, month, out, want)
				}
				for _, e := range out.Events {
					if e.Month != admissionMonths[e.RequestId] {
						t.Fatalf("stream moved admission month: %v", e)
					}
				}
			}
		})
	}
}

func TestLedgerConcurrentSameRequestChargesAndFinishesOnce(t *testing.T) {
	s, _ := fixture(t)
	e := event(nil, 1)
	const retries = 12
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < retries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if d, err := s.Admit(context.Background(), e); err != nil || !d.Allowed {
				t.Errorf("admission=%v error=%v", d, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	for i := 0; i < retries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d, err := s.Charge(context.Background(), &pb.ChargeRequest{RequestId: e.RequestId, RequestBytes: 3, ResponseBytes: 7}); err != nil || !d.Allowed || d.RequestBytes != 3 || d.ResponseBytes != 7 {
				t.Errorf("charge=%v error=%v", d, err)
			}
		}()
	}
	wg.Wait()
	for i := 0; i < retries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Finish(context.Background(), &pb.Event{RequestId: e.RequestId, Status: 200, ResponseBytes: 4, Forwarded: true}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	out := export(t, s, "2026-10")
	if len(out.Events) != 1 || out.OwnerUsage.Requests != 1 || out.OwnerUsage.AdmittedRequests != 1 || out.OwnerUsage.RequestBytes != 3 || out.OwnerUsage.ResponseBytes != 4 || !out.Events[0].Finished {
		t.Fatalf("duplicate operations changed accounting: %v", out)
	}
}

func TestLedgerWriteFailureRollsBackCountersAndEvent(t *testing.T) {
	for _, phase := range []string{"admit", "charge", "finish"} {
		t.Run(phase, func(t *testing.T) {
			s, db := fixture(t)
			e := event(nil, 1)
			if phase != "admit" {
				admit(t, s, e)
				charge(t, s, e.RequestId, 2, 5)
			}
			before := export(t, s, "2026-10")
			if _, err := db.Exec(`CREATE TRIGGER fail_event_insert BEFORE INSERT ON meter_events BEGIN SELECT RAISE(ABORT,'fixture event failure'); END`); err != nil {
				t.Fatal(err)
			}
			var err error
			switch phase {
			case "admit":
				_, err = s.Admit(context.Background(), e)
			case "charge":
				_, err = s.Charge(context.Background(), &pb.ChargeRequest{RequestId: e.RequestId, RequestBytes: 4, ResponseBytes: 8})
			case "finish":
				_, err = s.Finish(context.Background(), &pb.Event{RequestId: e.RequestId, Status: 200, ResponseBytes: 3})
			}
			if err == nil {
				t.Fatal("storage failure was ignored")
			}
			after := export(t, s, "2026-10")
			if !proto.Equal(before, after) {
				t.Fatalf("failed %s changed ledger: before=%v after=%v", phase, before, after)
			}
			if _, err := db.Exec("DROP TRIGGER fail_event_insert"); err != nil {
				t.Fatal(err)
			}
			switch phase {
			case "admit":
				if d := admit(t, s, e); !d.Allowed {
					t.Fatal(d)
				}
			case "charge":
				if d := charge(t, s, e.RequestId, 4, 8); !d.Allowed {
					t.Fatal(d)
				}
			case "finish":
				finish(t, s, e, 3)
			}
		})
	}
}

func TestLedgerActiveGrantKeepsUTCAdmissionMonth(t *testing.T) {
	s, _ := fixture(t)
	now := time.Date(2026, 11, 1, 1, 59, 59, 0, time.FixedZone("east", 2*3600))
	s.now = func() time.Time { return now }
	g := newGrant(t, s, 1, 10, 0)
	old := event(g, 1)
	if d := admit(t, s, old); !d.Allowed || d.RequestsRemaining != 0 {
		t.Fatal(d)
	}
	charge(t, s, old.RequestId, 3, 2)
	now = now.Add(time.Second)
	current := event(g, 2)
	if d := admit(t, s, current); !d.Allowed || d.BytesRemaining != 10 || d.RequestsRemaining != 0 {
		t.Fatal(d)
	}
	if d := charge(t, s, old.RequestId, 3, 10); d.Allowed || d.RequestBytes != 3 || d.ResponseBytes != 7 || d.Reason != "byte_budget" {
		t.Fatal(d)
	}
	if d := charge(t, s, current.RequestId, 2, 4); !d.Allowed || d.BytesRemaining != 4 {
		t.Fatal(d)
	}
	finish(t, s, old, 5)
	finish(t, s, current, 4)
	for _, tc := range []struct {
		month     string
		req, resp int64
	}{{"2026-10", 3, 5}, {"2026-11", 2, 4}} {
		out := export(t, s, tc.month)
		if out.OwnerUsage.Requests != 1 || out.OwnerUsage.AdmittedRequests != 1 || out.OwnerUsage.RequestBytes != tc.req || out.OwnerUsage.ResponseBytes != tc.resp || len(out.Events) != 1 || out.Events[0].Month != tc.month {
			t.Fatal(out)
		}
	}
}
