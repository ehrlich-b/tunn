package host

import (
	"context"
	"net"
	"testing"

	"github.com/ehrlich-b/tunn/internal/domains"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestDomainRPCRequiresNodeSecretAndSharesAuthority(t *testing.T) {
	_, registry, _ := domainProxyFixture(t)
	listener := domainRPCListener{bufconn.Listen(1 << 20)}
	server := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor("domain-node-secret")))
	pb.RegisterDomainsServer(server, registry)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	defer func() { _ = listener.Close() }()
	conn, err := grpc.NewClient("passthrough:///domain-authority", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	remote := &domains.Remote{Connection: func() *grpc.ClientConn { return conn }}
	owner := &pb.Owner{Owner: "ad38bf44-0c4a-40ce-bdee-2d8579bf63cc"}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "x-node-secret", "domain-node-secret")
	d, err := remote.Add(ctx, &pb.Domain{Name: "rpc.example.com", Tunnel: "site", Owner: owner.Owner})
	if err != nil || d.CnameTarget == "" {
		t.Fatalf("%v %v", d, err)
	}
	listed, err := remote.List(ctx, owner)
	if err != nil || len(listed.Domains) != 1 || listed.Domains[0].Name != d.Name {
		t.Fatalf("%v %v", listed, err)
	}
	if _, err := remote.Certificate(ctx, d); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("pending certificate served", err)
	}
	if _, err := remote.List(context.Background(), owner); status.Code(err) != codes.Unauthenticated {
		t.Fatal("untrusted node accepted", err)
	}
	if _, err := remote.List(ctx, owner); status.Code(err) != codes.PermissionDenied {
		t.Fatal("bad node was not blocked", err)
	}
}

type domainRPCListener struct{ *bufconn.Listener }

func (l domainRPCListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return domainRPCConn{c}, nil
}

type domainRPCConn struct{ net.Conn }

func (c domainRPCConn) RemoteAddr() net.Addr { return domainRPCAddr("domain-rpc-fixture") }

type domainRPCAddr string

func (a domainRPCAddr) Network() string { return "bufconn" }
func (a domainRPCAddr) String() string  { return string(a) }
