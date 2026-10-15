package common

import (
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"net/http"
	"reflect"
	"testing"
)

func TestRequestHeaderRepresentations(t *testing.T) {
	fields := []*pb.HttpHeader{{Name: "x-app", Value: "first, literal"}, {Name: "X-App", Value: "second"}, {Name: "Cookie", Value: "a=1"}, {Name: "Cookie", Value: "b=2"}, {Name: "Connection", Value: "X-Hop, keep-alive"}, {Name: "X-Hop", Value: "secret"}, {Name: "Keep-Alive", Value: "secret"}, {Name: "Tunn-Authorization", Value: "secret"}}
	got, err := DecodeHTTPRequestHeaders(map[string]string{"Authorization": "must-not-merge"}, fields, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Values("X-App"), []string{"first, literal", "second"}) || got.Get("Cookie") != "a=1; b=2" {
		t.Fatalf("headers: %v", got)
	}
	for _, key := range []string{"Authorization", "Tunn-Authorization", "Connection", "X-Hop", "Keep-Alive"} {
		if got.Get(key) != "" {
			t.Errorf("leaked %s", key)
		}
	}
	legacy, _ := EncodeHTTPRequestHeaders(http.Header{"Cookie": {"a=1", "b=2"}})
	if legacy["Cookie"] != "a=1; b=2" {
		t.Fatal(legacy)
	}
}

func TestRequestHeaderFramingRejections(t *testing.T) {
	for _, fields := range [][]*pb.HttpHeader{
		{{Name: "Host", Value: "a"}, {Name: "host", Value: "b"}},
		{{Name: "Authorization", Value: "a"}, {Name: "authorization", Value: "b"}},
		{{Name: "Content-Length", Value: "0"}, {Name: "content-length", Value: "0"}},
		{{Name: "Content-Length", Value: "0, 0"}},
		{{Name: "Content-Length", Value: "1"}},
		{{Name: "Content-Length", Value: "0"}, {Name: "Transfer-Encoding", Value: "chunked"}},
		{{Name: "Transfer-Encoding", Value: "chunked, chunked"}},
		{{Name: "Bad Name", Value: "value"}}, {{Name: "X-App", Value: "injected\r\nHeader: value"}},
		{{Name: "Connection", Value: "bad option"}}, {nil},
	} {
		if _, err := DecodeHTTPRequestHeaders(nil, fields, 0, false); err == nil {
			t.Errorf("accepted %v", fields)
		}
	}
	if _, err := DecodeHTTPRequestHeaders(map[string]string{"Content-Length": "0, 0"}, nil, 0, false); err == nil {
		t.Fatal("malformed legacy framing accepted")
	}
}
