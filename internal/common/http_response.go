package common

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// EncodeHTTPResponseHeaders retains each field line for upgraded receivers and
// the historical comma-joined map for old receivers. Ordering between names is
// immaterial; ordering of values belonging to the same name is preserved.
func EncodeHTTPResponseHeaders(header http.Header) (map[string]string, []*pb.HttpHeader) {
	legacy := make(map[string]string, len(header))
	keys := make([]string, 0, len(header))
	for name := range header {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	var fields []*pb.HttpHeader
	for _, name := range keys {
		values := header[name]
		legacy[name] = strings.Join(values, ", ")
		for _, value := range values {
			fields = append(fields, &pb.HttpHeader{Name: name, Value: value})
		}
	}
	return legacy, fields
}

// DecodeHTTPResponseHeaders selects one complete representation. Never merge
// the list with the fallback map, including when the list omits a map key.
func DecodeHTTPResponseHeaders(legacy map[string]string, fields []*pb.HttpHeader) http.Header {
	header := make(http.Header)
	if len(fields) > 0 {
		for _, field := range fields {
			if field != nil {
				header.Add(field.Name, field.Value)
			}
		}
	} else {
		for name, value := range legacy {
			header.Set(name, value)
		}
	}
	return header
}

func HTTPResponseHasBody(method string, status int) bool {
	return method != http.MethodHead && status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified
}

// HTTPResponseContentLength distinguishes a known zero length from an absent
// length. Malformed or repeated lengths cannot be used as completion evidence.
func HTTPResponseContentLength(header http.Header) (int64, error) {
	values := header.Values("Content-Length")
	if len(values) == 0 {
		return -1, nil
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("invalid response Content-Length")
	}
	value := strings.TrimSpace(values[0])
	if value == "" {
		return 0, fmt.Errorf("invalid response Content-Length")
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("invalid response Content-Length")
		}
	}
	length, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid response Content-Length")
	}
	return length, nil
}
