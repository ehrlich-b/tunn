package host

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestReleaseNativeInternalListenerAuthorization(t *testing.T) {
	p, client, _ := opsProxy(t)
	cancel, done := opsStart(t, p)
	opsWaitHealth(t, p, client, "/readyz", http.StatusOK)
	conn, err := grpc.NewClient("passthrough:///"+p.config.InternalGRPCPort, grpc.WithTransportCredentials(credentials.NewTLS(client.Transport.(*http.Transport).TLSClientConfig.Clone())))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	rpc := internalpb.NewInternalServiceClient(conn)
	trusted := metadata.AppendToOutgoingContext(ctx, "x-node-secret", p.config.NodeSecret)
	response, err := rpc.GetNodeInfo(trusted, &internalpb.NodeInfoRequest{})
	if err != nil || response.GetNodeId() != p.config.PublicAddr {
		t.Fatalf("authenticated internal RPC: %v %v", response, err)
	}
	// A denied node request blacklists its source immediately. Authenticate
	// first and remove this fixture's loopback block after the denial check.
	t.Cleanup(func() {
		ipBlacklist.Lock()
		delete(ipBlacklist.entries, "127.0.0.1")
		ipBlacklist.Unlock()
	})
	if _, err := rpc.GetNodeInfo(ctx, &internalpb.NodeInfoRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous internal RPC: %v", err)
	}
	cancel()
	if err := opsWaitStopped(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	opsAssertReleased(t, p)
}
