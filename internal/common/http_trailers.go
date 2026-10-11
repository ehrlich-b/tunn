package common

import (
	"fmt"
	"net/http"
	"sort"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"golang.org/x/net/http/httpguts"
)

const MaxHTTPResponseTrailerFields = 64
const MaxHTTPResponseTrailerBytes = 16 * 1024

// Trailer names are fixed at response metadata time. Undeclared trailers are
// unsupported; they must not become ordinary headers or disappear silently.
func HTTPResponseTrailerNames(trailer http.Header) ([]string, error) {
	set := make(map[string]bool)
	for name := range trailer {
		set[http.CanonicalHeaderKey(name)] = true
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, ValidateHTTPResponseTrailers(names, nil)
}

// The terminal frame is atomic and bounded: at most 64 declared names, 64
// field values, and 16 KiB total of declared names plus field names/values.
func ValidateHTTPResponseTrailers(names []string, fields []*pb.HttpHeader) error {
	if len(names) > MaxHTTPResponseTrailerFields || len(fields) > MaxHTTPResponseTrailerFields {
		return fmt.Errorf("response trailer field limit exceeded")
	}
	declared := make(map[string]bool, len(names))
	bytes := 0
	for _, name := range names {
		canonical := http.CanonicalHeaderKey(name)
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidTrailerHeader(name) || declared[canonical] {
			return fmt.Errorf("invalid response trailer declaration")
		}
		declared[canonical] = true
		bytes += len(name)
	}
	for _, field := range fields {
		if field == nil || !declared[http.CanonicalHeaderKey(field.Name)] {
			return fmt.Errorf("undeclared response trailer")
		}
		if !httpguts.ValidHeaderFieldName(field.Name) || !httpguts.ValidTrailerHeader(field.Name) || !httpguts.ValidHeaderFieldValue(field.Value) {
			return fmt.Errorf("invalid response trailer field")
		}
		bytes += len(field.Name) + len(field.Value)
	}
	if bytes > MaxHTTPResponseTrailerBytes {
		return fmt.Errorf("response trailer byte limit exceeded")
	}
	return nil
}
