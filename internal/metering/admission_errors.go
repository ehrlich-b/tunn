package metering

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const admissionErrorDomain = "metering.tunn"

// policyError marks a decision made by the ledger, rather than an error from
// the login-node connection or its internal authentication interceptor.
func policyError(code codes.Code, message string) error {
	s, err := status.New(code, message).WithDetails(&errdetails.ErrorInfo{
		Domain: admissionErrorDomain, Reason: "POLICY_DENIED",
	})
	if err != nil {
		return status.Error(code, message)
	}
	return s.Err()
}

// IsPolicyDenial recognizes explicit ledger validation and admission decisions
// on both local and remote backends. Untagged gRPC errors are authority faults.
func IsPolicyDenial(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	for _, detail := range s.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok || info.Domain != admissionErrorDomain {
			continue
		}
		switch info.Reason {
		case "POLICY_DENIED":
			switch s.Code() {
			case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound:
				return true
			}
		case "SHARING_RATE", "CAPACITY":
			return s.Code() == codes.ResourceExhausted
		}
	}
	return false
}

// Admission errors remain local sentinels and carry a stable, distinguishable
// reason over gRPC. Message text is never used to reconstruct their identity.
type admissionError struct{ message, reason string }

func (e *admissionError) Error() string { return e.message }

func (e *admissionError) GRPCStatus() *status.Status {
	s := status.New(codes.ResourceExhausted, e.message)
	detailed, err := s.WithDetails(&errdetails.ErrorInfo{Domain: admissionErrorDomain, Reason: e.reason})
	if err != nil {
		return s
	}
	return detailed
}

func decodeAdmissionError(err error) error {
	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.ResourceExhausted {
		return err
	}
	for _, detail := range s.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok || info.Domain != admissionErrorDomain {
			continue
		}
		switch info.Reason {
		case "SHARING_RATE":
			return ErrSharingRate
		case "CAPACITY":
			return ErrCapacity
		}
	}
	return err
}
