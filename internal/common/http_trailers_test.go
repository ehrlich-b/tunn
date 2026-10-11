package common

import (
	"fmt"
	"strings"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestHTTPFidelityTrailerBounds(t *testing.T) {
	for _, c := range []struct {
		name   string
		names  []string
		fields []*pb.HttpHeader
	}{
		{"undeclared", []string{"X-End"}, []*pb.HttpHeader{{Name: "X-Other", Value: "no"}}},
		{"forbidden", []string{"Content-Length"}, nil},
		{"duplicate", []string{"X-End", "x-end"}, nil},
		{"invalid-value", []string{"X-End"}, []*pb.HttpHeader{{Name: "X-End", Value: "one\r\nInjected: bad"}}},
		{"oversized-value", []string{"X-End"}, []*pb.HttpHeader{{Name: "X-End", Value: strings.Repeat("x", MaxHTTPResponseTrailerBytes)}}},
		{"nil-field", []string{"X-End"}, []*pb.HttpHeader{nil}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateHTTPResponseTrailers(c.names, c.fields); err == nil {
				t.Fatal("invalid terminal fields accepted")
			}
		})
	}
	names := make([]string, MaxHTTPResponseTrailerFields)
	fields := make([]*pb.HttpHeader, len(names))
	for i := range names {
		names[i] = fmt.Sprintf("X-%02d", i)
		fields[i] = &pb.HttpHeader{Name: names[i], Value: "one"}
	}
	if err := ValidateHTTPResponseTrailers(names, fields); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHTTPResponseTrailers(names, append(fields, &pb.HttpHeader{Name: names[0], Value: "two"})); err == nil {
		t.Fatal("field count bound not enforced")
	}
	if err := ValidateHTTPResponseTrailers(append(names, "X-Extra"), nil); err == nil {
		t.Fatal("declaration bound not enforced")
	}
	fields = []*pb.HttpHeader{{Name: "X-End", Value: strings.Repeat("x", MaxHTTPResponseTrailerBytes-2*len("X-End"))}}
	if err := ValidateHTTPResponseTrailers([]string{"X-End"}, fields); err != nil {
		t.Fatal("exact byte boundary:", err)
	}
}
