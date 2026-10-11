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
