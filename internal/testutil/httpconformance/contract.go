// Package httpconformance supplies fixtures and an independent response oracle
// shared by the SDK wire tests and the relay's HTTP consumer tests.
package httpconformance

import (
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

type Generation string

const (
	Legacy  Generation = "legacy-map"
	Current Generation = "current-list"
)

type Mode string

const (
	Buffered  Mode = "buffered"
	Streaming Mode = "streaming"
)

type Cell struct {
	Publisher, Relay Generation
	Mode             Mode
}

func (c Cell) String() string { return fmt.Sprintf("%s/%s/%s", c.Publisher, c.Relay, c.Mode) }
func (c Cell) Exact() bool    { return c.Publisher == Current && c.Relay == Current }
func Cells() []Cell {
	var cells []Cell
	for _, publisher := range []Generation{Legacy, Current} {
		for _, relay := range []Generation{Legacy, Current} {
			for _, mode := range []Mode{Buffered, Streaming} {
				cells = append(cells, Cell{publisher, relay, mode})
			}
		}
	}
	return cells
}

// Observation deliberately has no protobuf dependency. Want comes from a real
// direct net/http response, never from the tunnel's header codec.
type Observation struct {
	Status          int
	Header, Trailer http.Header
	Body            string
	ReadErr         error
	Terminals       int
}

func Read(response *http.Response) Observation {
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return Observation{Status: response.StatusCode, Header: response.Header.Clone(), Trailer: response.Trailer.Clone(), Body: string(body), ReadErr: err, Terminals: 1}
}

// Assert compares semantic fields only: HTTP framing and Date are hop-specific.
// The exact per-name slices detect merged maps/lists and doubled field values.
func Assert(t *testing.T, got, want Observation) {
	t.Helper()
	if got.Status != want.Status || got.Body != want.Body || (got.ReadErr == nil) != (want.ReadErr == nil) || got.Terminals != want.Terminals {
		t.Fatalf("response got status=%d body=%q err=%v terminals=%d; want status=%d body=%q err=%v terminals=%d", got.Status, got.Body, got.ReadErr, got.Terminals, want.Status, want.Body, want.ReadErr, want.Terminals)
	}
	for _, name := range []string{"Set-Cookie", "X-Repeat", "X-Map-Only", "Content-Type"} {
		if !reflect.DeepEqual(got.Header.Values(name), want.Header.Values(name)) {
			t.Fatalf("%s: got %q; want %q", name, got.Header.Values(name), want.Header.Values(name))
		}
	}
	// The relay may add its own metering terminal trailer and reframe body
	// length. Content-Length preservation is checked at the SDK wire boundary;
	// downstream length correctness is checked with actual interrupted reads.
	got.Trailer = got.Trailer.Clone()
	got.Trailer.Del("Tunn-Limit-Reason")
	if len(got.Trailer) != len(want.Trailer) {
		t.Fatalf("trailers: got %v; want %v", got.Trailer, want.Trailer)
	}
	for name, values := range want.Trailer {
		if !reflect.DeepEqual(got.Trailer.Values(name), values) {
			t.Fatalf("trailer %s: got %v; want %v", name, got.Trailer.Values(name), values)
		}
	}
}

// LegacyWireExpectation describes the documented comma-joined map, independent
// of production codecs. The relay's historical cookie split has a separate
// literal expectation in the HTTP consumer test.
func LegacyWireExpectation(reference Observation) Observation {
	want := reference
	want.Header = reference.Header.Clone()
	for name, values := range want.Header {
		want.Header[name] = []string{strings.Join(values, ", ")}
	}
	return want
}

type Scenario struct {
	Name     string
	Handler  http.Handler
	Trailers bool
}

func Scenarios() []Scenario {
	return []Scenario{
		{"cookies", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Add("X-Repeat", "one,two")
			w.Header().Add("X-Repeat", "three")
			w.Header().Add("Set-Cookie", "first=one,fragment=two; Path=/")
			w.Header().Add("Set-Cookie", "second=three; Path=/")
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, "abc")
		}), false},
		{"status-only", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }), false},
		{"flushed", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, "abc")
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, "def")
		}), false},
		{"trailers", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Add("Trailer", "X-End")
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, "abc")
			w.(http.Flusher).Flush()
			w.Header().Add("X-End", "one,two")
			w.Header().Add("X-End", "three")
		}), true},
	}
}

// LegacyResponseDescriptor is an independent pre-list schema snapshot. Field
// numbers/types are literals, never derived from the current descriptor.
func LegacyResponseDescriptor(t *testing.T, buffered bool) protoreflect.MessageDescriptor {
	t.Helper()
	optional, repeated := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	str, integer, message, bytes := descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_TYPE_INT32, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, descriptorpb.FieldDescriptorProto_TYPE_BYTES
	field := func(name string, number int32, kind descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(number), Type: &kind, Label: &optional}
	}
	fields := []*descriptorpb.FieldDescriptorProto{field("status_code", 1, integer), field("headers", 2, message)}
	if buffered {
		fields = []*descriptorpb.FieldDescriptorProto{field("connection_id", 1, str), field("status_code", 2, integer), field("headers", 3, message), field("body", 4, bytes)}
	}
	headers := fields[1]
	if buffered {
		headers = fields[2]
	}
	headers.Label = &repeated
	headers.TypeName = proto.String(".legacy.Response.HeadersEntry")
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("legacy-response.proto"), Package: proto.String("legacy"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Response"), Field: fields, NestedType: []*descriptorpb.DescriptorProto{{Name: proto.String("HeadersEntry"), Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)}, Field: []*descriptorpb.FieldDescriptorProto{field("key", 1, str), field("value", 2, str)}}}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return file.Messages().ByName("Response")
}

// WireResponse actually serializes through the independent legacy schema for
// an old sender or receiver. Unknown fields are discarded as an old endpoint
// does when reconstructing HTTP. It never merely clears current struct fields.
func WireResponse(t *testing.T, original proto.Message, cell Cell) proto.Message {
	t.Helper()
	wire, err := proto.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, generation := range []Generation{cell.Publisher, cell.Relay} {
		if generation != Legacy {
			continue
		}
		old := dynamicpb.NewMessage(LegacyResponseDescriptor(t, cell.Mode == Buffered))
		if err = proto.Unmarshal(wire, old); err != nil {
			t.Fatal(err)
		}
		old.SetUnknown(nil)
		wire, err = proto.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
	}
	decoded := original.ProtoReflect().Type().New().Interface()
	if err = proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}
