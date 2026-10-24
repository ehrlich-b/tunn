package host

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/domains"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This is an allowlist, never a dump of a request, response, or dependency error.
func enrollmentCategory(w *httptest.ResponseRecorder) string {
	if w.Code < 400 {
		return "ok"
	}
	switch strings.TrimSpace(w.Body.String()) {
	case `{"error":"App device authority unavailable"}`:
		return "app-authority-unavailable"
	case "App device authority unavailable":
		return "authentication-authority-unavailable"
	}
	if w.Code == 403 {
		return "scope-denied"
	}
	return "other-safe-error"
}

func enrollmentDiagnostic(t *testing.T, schedule, stage string, w *httptest.ResponseRecorder, started time.Time, ready bool) {
	t.Helper()
	record := struct {
		Schedule string `json:"schedule"`
		Stage    string `json:"stage"`
		Status   int    `json:"status"`
		Category string `json:"category"`
		Elapsed  int64  `json:"elapsed_ns"`
		Ready    bool   `json:"fixture_ready"`
	}{schedule, stage, w.Code, enrollmentCategory(w), time.Since(started).Nanoseconds(), ready}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ENROLLMENT_DIAGNOSTIC %s", data)
}

type enrollmentDomainSchedule struct {
	domains.Backend
	schedule string
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
	ready    atomic.Bool
}

func (s *enrollmentDomainSchedule) Route(ctx context.Context, in *domainpb.Domain) (*domainpb.Domain, error) {
	s.once.Do(func() { close(s.entered) })
	switch s.schedule {
	case "delayed-ready":
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	case "unavailable":
		return nil, status.Error(codes.Unavailable, "diagnostic dependency unavailable")
	case "canceled":
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		return nil, canceled.Err()
	}
	return s.Backend.Route(ctx, in)
}

func TestAppDeviceEnrollmentDiagnosticMatrix(t *testing.T) {
	for _, schedule := range []string{"successful", "delayed-ready", "unavailable", "canceled", "namespace-mutation"} {
		t.Run(schedule, func(t *testing.T) {
			started := time.Now()
			f := newAppDeviceFixture(t)
			if err := f.db.PingContext(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := f.p.domains.Route(context.Background(), &domainpb.Domain{Name: appDeviceTestHost}); err != nil {
				t.Fatal(err)
			}
			invitation := f.invite(t, nil)
			verifier, err := randomOAuthValue("")
			if err != nil {
				t.Fatal(err)
			}
			claim := f.claim(t, invitation, verifier)
			backend := &enrollmentDomainSchedule{Backend: f.p.domains, schedule: schedule, entered: make(chan struct{}), release: make(chan struct{})}
			backend.ready.Store(schedule == "successful" || schedule == "namespace-mutation")
			f.p.domains = backend
			if schedule == "namespace-mutation" {
				if _, err := backend.Delete(context.Background(), &domainpb.Domain{Name: "*.apps.test", Owner: f.tunnel.AccountID}); err != nil {
					t.Fatal(err)
				}
			}
			if schedule == "delayed-ready" {
				done := make(chan struct{})
				go func() { defer close(done); <-backend.entered; backend.ready.Store(true); close(backend.release) }()
				defer func() { <-done }()
			}
			enrollmentDiagnostic(t, schedule, "fixture", httptest.NewRecorder(), started, backend.ready.Load())
			w := f.approve(t, claim, nil)
			enrollmentDiagnostic(t, schedule, "approve", w, started, backend.ready.Load())
			want, category := 200, "ok"
			if schedule == "unavailable" || schedule == "canceled" {
				want, category = 503, "app-authority-unavailable"
			}
			if schedule == "namespace-mutation" {
				want, category = 403, "scope-denied"
			}
			if w.Code != want || enrollmentCategory(w) != category {
				t.Fatalf("approval status=%d category=%s want=%d/%s", w.Code, enrollmentCategory(w), want, category)
			}
			// Failed approval must not issue a device or create a stream.
			var devices, approved int
			if err := f.db.QueryRow(`SELECT count(*) FROM app_devices`).Scan(&devices); err != nil {
				t.Fatal(err)
			}
			if err := f.db.QueryRow(`SELECT approved FROM app_device_invitations WHERE id=?`, invitation.ID).Scan(&approved); err != nil {
				t.Fatal(err)
			}
			if devices != 0 || (approved == 1) != (want == 200) {
				t.Fatal("approval issuance/state mismatch")
			}
			if want == 200 {
				w = f.redeem(t, claim, verifier, true)
				enrollmentDiagnostic(t, schedule, "redeem", w, started, backend.ready.Load())
				if w.Code != 201 {
					t.Fatalf("redeem status=%d", w.Code)
				}
			}
		})
	}
}
