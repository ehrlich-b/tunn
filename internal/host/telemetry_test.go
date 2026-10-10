package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ehrlich-b/tunn/internal/metering"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestInspectContractRelayObservesQuotaAndCorrelation(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			p, _, ledger, stream := meteringRelay(t, streaming, "ok")
			_, token := relayGrant(t, ledger, 1, 100)
			previous := stream.hook
			var mu sync.Mutex
			var id string
			var active int64
			stream.hook = func(msg *pb.TunnelMessage) error {
				mu.Lock()
				if request := msg.GetHttpRequest(); request != nil {
					id = request.ConnectionId
					active = p.OperationalMetrics().ActiveStreams
				}
				if open := msg.GetConnectionOpen(); open != nil {
					id = open.ConnectionId
					active = p.OperationalMetrics().ActiveStreams
				}
				mu.Unlock()
				return previous(msg)
			}
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, relayRequest(token, ""))
			mu.Lock()
			observedID, observedActive := id, active
			mu.Unlock()
			if rec.Code != 200 || observedActive != 1 || observedID == "" || observedID != rec.Header().Get("Tunn-Request-ID") {
				t.Fatalf("correlation=%q header=%q active=%d status=%d", observedID, rec.Header().Get("Tunn-Request-ID"), observedActive, rec.Code)
			}
			rec = httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, relayRequest(token, ""))
			if rec.Code != 429 || p.OperationalMetrics().DeniedAdmissions != 1 || p.OperationalMetrics().ActiveStreams != 0 || p.OperationalMetrics().ExportDrops != 0 {
				t.Fatalf("status=%d metrics=%+v", rec.Code, p.OperationalMetrics())
			}
			out := relayExport(t, ledger)
			if out.OwnerUsage.AdmittedRequests != 1 || out.OwnerUsage.Requests != 2 || out.OwnerUsage.ResponseBytes != 2 {
				t.Fatalf("observer changed accounting: %+v", out.OwnerUsage)
			}
		})
	}
}

type inspectContractFailedFinish struct{ metering.Backend }

func (b inspectContractFailedFinish) Finish(context.Context, *meterpb.Event) (*emptypb.Empty, error) {
	return nil, errors.New("fixture audit export failure")
}
func TestInspectContractRelayExportDrops(t *testing.T) {
	p, _, ledger, _ := meteringRelay(t, false, "ok")
	_, token := relayGrant(t, ledger, 2, 100)
	p.meter = inspectContractFailedFinish{p.meter}
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, relayRequest(token, ""))
	if rec.Code != 200 || p.OperationalMetrics().ActiveStreams != 0 || p.OperationalMetrics().ExportDrops != 1 || p.OperationalMetrics().DeniedAdmissions != 0 {
		t.Fatalf("status=%d metrics=%+v", rec.Code, p.OperationalMetrics())
	}
}

func TestInspectContractRelayRedirectDenialAndSafeLogs(t *testing.T) {
	var log bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	p, _, ledger, _ := meteringRelay(t, false, "ok")
	r := httptest.NewRequest("GET", "https://api.tunn.test/hook?token=QUERY_SENTINEL", nil)
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, r)
	out := relayExport(t, ledger)
	if rec.Code != 302 || p.OperationalMetrics().DeniedAdmissions != 1 || p.OperationalMetrics().ActiveStreams != 0 || len(out.Events) != 1 || out.Events[0].Allowed || out.Events[0].Reason != "authentication_required" {
		t.Fatalf("redirect=%d metrics=%+v audit=%+v", rec.Code, p.OperationalMetrics(), out.Events)
	}
	if strings.Contains(log.String(), "QUERY_SENTINEL") {
		t.Fatalf("credential query logged: %s", log.String())
	}
}
