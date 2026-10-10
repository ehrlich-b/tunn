package host

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

type prodAuthRPCListener struct{ *bufconn.Listener }
type prodAuthRPCConn struct{ net.Conn }

func (l prodAuthRPCListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return prodAuthRPCConn{conn}, nil
}

// Memory transports have no IP. This keeps a preceding principal's temporary
// IP block from replacing the credential decision for the next matrix case.
func (c prodAuthRPCConn) RemoteAddr() net.Addr { return &net.UnixAddr{Net: "memory"} }

// Discover all internal unary methods from the production proto descriptors,
// then invoke the actual registered services through gRPC's public interface.
func TestProdAuthInternalRPCPrincipalMatrix(t *testing.T) {
	f := newProdAuthFixture(t)
	const secret = "auth-node-fixture-secret"
	var delivered atomic.Int64
	guard := nodeSecretInterceptor(secret)
	server := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return guard(ctx, request, info, func(ctx context.Context, request any) (any, error) {
			delivered.Add(1)
			return handler(ctx, request)
		})
	}))
	internalpb.RegisterInternalServiceServer(server, NewInternalServer(f.p.tunnelServer, "tunn.test", true))
	internalpb.RegisterLoginNodeDBServer(server, NewLoginNodeDBServer(f.p.storage.(*storage.LocalStorage)))
	meterpb.RegisterMeteringServer(server, f.p.meter.(*metering.Store))
	domainpb.RegisterDomainsServer(server, f.p.domains.(*domains.Registry))
	listener := prodAuthRPCListener{bufconn.Listen(1 << 20)}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	conn, err := grpc.NewClient("passthrough:///auth-internal-fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	principals := []struct {
		name, node, bearer string
		allow              bool
	}{
		{"anonymous", "", "", false},
		{"wrong-node", "other-node-secret", "", false},
		{"owner-as-node", f.credentials["owner-jwt"], "", false},
		{"grant-as-node", f.credentials["consumer-grant"], "", false},
		{"mcp-as-node", f.credentials["mcp-oauth"], "", false},
		{"owner-bearer", "", f.credentials["owner-jwt"], false},
		{"node", secret, "", true},
	}
	methods := 0
	for _, file := range []protoreflect.FileDescriptor{internalpb.File_proto_internal_proto, meterpb.File_proto_metering_proto, domainpb.File_proto_domains_proto} {
		services := file.Services()
		for i := 0; i < services.Len(); i++ {
			service := services.Get(i)
			for j := 0; j < service.Methods().Len(); j++ {
				method := service.Methods().Get(j)
				if method.IsStreamingClient() || method.IsStreamingServer() {
					t.Fatalf("internal streaming method %s needs a principal matrix", method.FullName())
				}
				methods++
				name := "/" + string(service.FullName()) + "/" + string(method.Name())
				for _, principal := range principals {
					t.Run(name+"/"+principal.name, func(t *testing.T) {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						if principal.node != "" {
							ctx = metadata.AppendToOutgoingContext(ctx, "x-node-secret", principal.node)
						}
						if principal.bearer != "" {
							ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+principal.bearer)
						}
						before := delivered.Load()
						err := conn.Invoke(ctx, name, dynamicpb.NewMessage(method.Input()), dynamicpb.NewMessage(method.Output()))
						if !principal.allow {
							if status.Code(err) != codes.Unauthenticated || delivered.Load() != before {
								t.Fatalf("internal authorization returned %v; handler deliveries = %d", err, delivered.Load()-before)
							}
						} else if status.Code(err) == codes.Unauthenticated || delivered.Load() != before+1 {
							t.Fatalf("node credential failed to reach handler: %v", err)
						}
					})
				}
			}
		}
	}
	if methods == 0 {
		t.Fatal("internal RPC descriptors did not enumerate any methods")
	}
	t.Logf("checked %d internal RPC methods against %d principals", methods, len(principals))
}
