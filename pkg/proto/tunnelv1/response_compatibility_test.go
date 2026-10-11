package tunnelv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// An independent minimal snapshot of the pre-list wire contract. It deliberately
// does not derive field numbers or types from the upgraded descriptor.
func legacyResponseDescriptor(t *testing.T, buffered bool) protoreflect.MessageDescriptor {
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
	headers := fields[len(fields)-1]
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

func TestHTTPFidelityWireVersions(t *testing.T) {
	for _, buffered := range []bool{true, false} {
		name := "streaming"
		if buffered {
			name = "buffered"
		}
		t.Run(name, func(t *testing.T) {
			old := dynamicpb.NewMessage(legacyResponseDescriptor(t, buffered))
			fields := []*HttpHeader{{Name: "Set-Cookie", Value: "one=a,b=c; Path=/"}, {Name: "Set-Cookie", Value: "two=d; Path=/"}, {Name: "X-Repeat", Value: "first"}, {Name: "X-Repeat", Value: "second"}}
			fallback := map[string]string{"Set-Cookie": "one=a,b=c; Path=/, two=d; Path=/", "X-Repeat": "first, second"}
			var upgraded, decoded proto.Message
			if buffered {
				upgraded = &HttpResponse{ConnectionId: "legacy", StatusCode: 202, Headers: fallback, Body: []byte("body"), HeaderFields: fields}
				decoded = &HttpResponse{}
			} else {
				upgraded = &HttpResponseHead{StatusCode: 202, Headers: fallback, HeaderFields: fields}
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
				if len(r.HeaderFields) != 0 || r.Headers["X-Repeat"] != "first, second" {
					t.Fatal("old-client/new-host decode")
				}
			} else {
				r := decoded.(*HttpResponseHead)
				if len(r.HeaderFields) != 0 || r.Headers["X-Repeat"] != "first, second" {
					t.Fatal("old-client/new-host decode")
				}
			}
		})
	}
}
