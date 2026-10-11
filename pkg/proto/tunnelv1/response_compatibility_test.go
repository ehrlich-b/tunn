package tunnelv1

import (
	"testing"

	"github.com/ehrlich-b/tunn/internal/testutil/httpconformance"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestHTTPFidelityWireVersions(t *testing.T) {
	for _, buffered := range []bool{true, false} {
		name := "streaming"
		if buffered {
			name = "buffered"
		}
		t.Run(name, func(t *testing.T) {
			old := dynamicpb.NewMessage(httpconformance.LegacyResponseDescriptor(t, buffered))
			fields := []*HttpHeader{{Name: "Set-Cookie", Value: "one=a,b=c; Path=/"}, {Name: "Set-Cookie", Value: "two=d; Path=/"}, {Name: "X-Repeat", Value: "first"}, {Name: "X-Repeat", Value: "second"}}
			fallback := map[string]string{"Set-Cookie": "one=a,b=c; Path=/, two=d; Path=/", "X-Repeat": "first, second"}
			var upgraded, decoded proto.Message
			if buffered {
				upgraded = &HttpResponse{ConnectionId: "legacy", StatusCode: 202, Headers: fallback, Body: []byte("body"), HeaderFields: fields, TrailerNames: []string{"X-End"}, Trailers: []*HttpHeader{{Name: "X-End", Value: "done"}}}
				decoded = &HttpResponse{}
			} else {
				upgraded = &HttpResponseHead{StatusCode: 202, Headers: fallback, HeaderFields: fields, TrailerNames: []string{"X-End"}}
				decoded = &HttpResponseHead{}
			}
			wire, err := proto.Marshal(upgraded)
			if err != nil {
				t.Fatal(err)
			}
			if err = proto.Unmarshal(wire, old); err != nil {
				t.Fatal(err)
			}
			if old.Get(old.Descriptor().Fields().ByName("status_code")).Int() != 202 {
				t.Fatal("new client changed legacy status")
			}
			headers := old.Get(old.Descriptor().Fields().ByName("headers")).Map()
			if headers.Len() != 2 || headers.Get(protoreflect.ValueOfString("Set-Cookie").MapKey()).String() != fallback["Set-Cookie"] {
				t.Fatal("new client lost old-host fallback")
			}
			if buffered && string(old.Get(old.Descriptor().Fields().ByName("body")).Bytes()) != "body" {
				t.Fatal("legacy body changed")
			}
			// A genuinely old sender has no list, including unknown fields.
			old.SetUnknown(nil)
			oldWire, err := proto.Marshal(old)
			if err != nil {
				t.Fatal(err)
			}
			if err = proto.Unmarshal(oldWire, decoded); err != nil {
				t.Fatal(err)
			}
			if buffered {
				r := decoded.(*HttpResponse)
				if len(r.HeaderFields) != 0 || len(r.TrailerNames) != 0 || r.Headers["X-Repeat"] != "first, second" {
					t.Fatal("old-client/new-host decode")
				}
			} else {
				r := decoded.(*HttpResponseHead)
				if len(r.HeaderFields) != 0 || len(r.TrailerNames) != 0 || r.Headers["X-Repeat"] != "first, second" {
					t.Fatal("old-client/new-host decode")
				}
			}
		})
	}
}

func TestHTTPFidelityLegacyTerminalFrame(t *testing.T) {
	// The pre-trailer terminal frame contains only string connection_id = 1.
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{Name: proto.String("old-terminal.proto"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Terminal"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("connection_id"), Number: proto.Int32(1), Label: &optional, Type: &str}}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	old := dynamicpb.NewMessage(file.Messages().Get(0))
	wire, err := proto.Marshal(&ConnectionHalfClose{ConnectionId: "complete", Trailers: []*HttpHeader{{Name: "X-End", Value: "done"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = proto.Unmarshal(wire, old); err != nil {
		t.Fatal(err)
	}
	if old.Get(old.Descriptor().Fields().ByNumber(1)).String() != "complete" || len(old.GetUnknown()) == 0 {
		t.Fatal("old receiver did not retain its terminal contract")
	}
	old.SetUnknown(nil)
	wire, err = proto.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &ConnectionHalfClose{}
	if err = proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ConnectionId != "complete" || len(decoded.Trailers) != 0 {
		t.Fatal("legacy terminal frame invented trailer support")
	}
}
