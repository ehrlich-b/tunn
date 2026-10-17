package metering

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestR4AdmissionTranslationRequiresTypedAuthorityReason(t *testing.T) {
	typed := func(code codes.Code, domain, reason string) error {
		t.Helper()
		s, err := status.New(code, ErrSharingRate.Error()).WithDetails(&errdetails.ErrorInfo{Domain: domain, Reason: reason})
		if err != nil {
			t.Fatal(err)
		}
		return s.Err()
	}
	for _, err := range []error{
		nil,
		errors.New(ErrSharingRate.Error()),
		status.Error(codes.ResourceExhausted, ErrSharingRate.Error()),
		typed(codes.ResourceExhausted, "other-service", "SHARING_RATE"),
		typed(codes.ResourceExhausted, admissionErrorDomain, "OTHER_LIMIT"),
		typed(codes.PermissionDenied, admissionErrorDomain, "SHARING_RATE"),
		status.Error(codes.Unavailable, "authority unavailable"),
		status.Error(codes.DeadlineExceeded, "authority timeout"),
	} {
		if got := decodeAdmissionError(err); got != err {
			t.Fatalf("unrecognized error changed: %v -> %v", err, got)
		}
	}
	for _, sentinel := range []error{ErrSharingRate, ErrCapacity} {
		// Wrapping retains both local identity and the wire details.
		wrapped := fmt.Errorf("authority admission: %w", sentinel)
		if !errors.Is(wrapped, sentinel) {
			t.Fatal("local sentinel identity lost")
		}
		if got := decodeAdmissionError(status.Convert(wrapped).Err()); got != sentinel {
			t.Fatalf("wrapped admission translation=%v want=%v", got, sentinel)
		}
	}
}

func TestPolicyDenialRequiresLedgerDetails(t *testing.T) {
	for _, code := range []codes.Code{codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound} {
		local := policyError(code, "ledger decision")
		for _, err := range []error{local, fmt.Errorf("wrapped: %w", local), status.Convert(local).Err()} {
			if !IsPolicyDenial(err) || status.Code(err) != code {
				t.Fatalf("ledger decision lost identity or code: %v", err)
			}
		}
		if IsPolicyDenial(status.Error(code, "ledger decision")) {
			t.Fatalf("untagged %v treated as policy denial", code)
		}
	}
	for _, err := range []error{ErrSharingRate, ErrCapacity} {
		if !IsPolicyDenial(err) || !IsPolicyDenial(status.Convert(err).Err()) {
			t.Fatalf("admission decision lost identity: %v", err)
		}
	}
	for _, test := range []struct {
		code           codes.Code
		domain, reason string
	}{
		{codes.FailedPrecondition, "other-service", "POLICY_DENIED"},
		{codes.FailedPrecondition, admissionErrorDomain, "UNKNOWN_REASON"},
		{codes.Unavailable, admissionErrorDomain, "POLICY_DENIED"},
		{codes.FailedPrecondition, admissionErrorDomain, "CAPACITY"},
	} {
		s, err := status.New(test.code, "connection diagnostic").WithDetails(&errdetails.ErrorInfo{Domain: test.domain, Reason: test.reason})
		if err != nil {
			t.Fatal(err)
		}
		if IsPolicyDenial(s.Err()) {
			t.Fatalf("unrecognized ledger details treated as policy denial: %v", s.Err())
		}
	}
	if IsPolicyDenial(nil) || IsPolicyDenial(errors.New("storage unavailable")) {
		t.Fatal("non-policy error treated as denial")
	}
}
