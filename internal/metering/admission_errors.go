package metering

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const admissionErrorDomain = "metering.tunn"

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
