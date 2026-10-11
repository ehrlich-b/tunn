package common

import (
	"net/http"
	"reflect"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestHTTPFidelityHeaderPrecedence(t *testing.T) {
	legacy := map[string]string{"Set-Cookie": "stale=map", "X-Repeat": "joined", "X-Map-Only": "must disappear"}
	fields := []*pb.HttpHeader{{Name: "set-cookie", Value: "one=a,b=c"}, {Name: "Set-Cookie", Value: "two=d"}, {Name: "X-Repeat", Value: "one"}, {Name: "x-repeat", Value: "two"}}
	got := DecodeHTTPResponseHeaders(legacy, fields)
	if got.Get("X-Map-Only") != "" || !reflect.DeepEqual(got.Values("X-Repeat"), []string{"one", "two"}) || len(got.Values("Set-Cookie")) != 2 {
		t.Fatalf("precedence: %v", got)
	}
	for _, empty := range [][]*pb.HttpHeader{nil, {}} {
		if got := DecodeHTTPResponseHeaders(legacy, empty); got.Get("X-Map-Only") != "must disappear" {
			t.Fatal("empty-list fallback")
		}
	}
}

func TestHTTPFidelityHeaderEncoding(t *testing.T) {
	original := http.Header{"Set-Cookie": {"one=a,b=c", "two=d"}, "X-Repeat": {"one,two", "three"}}
	legacy, fields := EncodeHTTPResponseHeaders(original)
	if legacy["X-Repeat"] != "one,two, three" {
		t.Fatalf("legacy fallback: %v", legacy)
	}
	if !reflect.DeepEqual(DecodeHTTPResponseHeaders(legacy, fields), original) {
		t.Fatal("field lines did not round trip")
	}
}

func TestHTTPFidelityContentLength(t *testing.T) {
	for _, c := range []struct {
		values  []string
		want    int64
		invalid bool
	}{{nil, -1, false}, {[]string{"0"}, 0, false}, {[]string{"3"}, 3, false}, {[]string{"-1"}, 0, true}, {[]string{""}, 0, true}, {[]string{"3, 3"}, 0, true}, {[]string{"3", "3"}, 0, true}, {[]string{"+3"}, 0, true}, {[]string{"9223372036854775808"}, 0, true}} {
		header := make(http.Header)
		if c.values != nil {
			header["Content-Length"] = c.values
		}
		got, err := HTTPResponseContentLength(header)
		if (err != nil) != c.invalid || (!c.invalid && got != c.want) {
			t.Fatalf("Content-Length %v: %d %v", c.values, got, err)
		}
	}
}
