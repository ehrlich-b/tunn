package host

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestMeteringInternalAuthoritySharesBudgetsAcrossRelays(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ledger, err := metering.New(db)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := relayGrant(t, ledger, 2, 10)
	listener := bufconn.Listen(1 << 20)
	defer func() { _ = listener.Close() }()
	server := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor("fixture-node-secret")))
	pb.RegisterMeteringServer(server, ledger)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///metering-fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-node-secret", "fixture-node-secret"))
	first := &metering.Remote{Connection: func() *grpc.ClientConn { return conn }}
	second := &metering.Remote{Connection: func() *grpc.ClientConn { return conn }}

	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 1; i <= 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			relay := first
			if n%2 == 0 {
				relay = second
			}
			e := &pb.Event{RequestId: fmt.Sprintf("%032x", n), Owner: g.Owner, Endpoint: g.Endpoint, Caller: "grant:" + g.Id, GrantId: g.Id, AuthMethod: "grant", Allowed: true, Reason: "allowed"}
			d, err := relay.Admit(ctx, e)
			if err != nil {
				t.Error(err)
				return
			}
			if !d.Allowed {
				if d.Reason != "request_budget" {
					t.Error(d)
				}
				return
			}
			mu.Lock()
			admitted++
			mu.Unlock()
			charge := &pb.ChargeRequest{RequestId: e.RequestId, RequestBytes: 2, ResponseBytes: 3}
			if d, err := relay.Charge(ctx, charge); err != nil || !d.Allowed {
				t.Errorf("charge=%v %v", d, err)
			}
			// A duplicate internal RPC reserves no additional bytes.
			if d, err := relay.Charge(ctx, charge); err != nil || !d.Allowed {
				t.Errorf("charge retry=%v %v", d, err)
			}
			if _, err := relay.Finish(ctx, &pb.Event{RequestId: e.RequestId, Status: 200, Forwarded: true, ResponseBytes: 3}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if admitted != 2 {
		t.Fatal(admitted)
	}
	out, err := first.Export(ctx, &pb.ExportRequest{Owner: g.Owner, Endpoint: g.Endpoint, Month: time.Now().UTC().Format("2006-01")})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Usage) != 1 || out.Usage[0].Requests != 10 || out.Usage[0].AdmittedRequests != 2 || out.Usage[0].RequestBytes != 4 || out.Usage[0].ResponseBytes != 6 {
		t.Fatal(out)
	}
	if _, err := first.RevokeGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	// Invalid credentials deliberately trigger the production IP blacklist; test
	// this after legitimate calls and clear only this fixture address on cleanup.
	t.Cleanup(func() { ipBlacklist.Lock(); delete(ipBlacklist.entries, "bufconn"); ipBlacklist.Unlock() })
	if _, err := first.Export(context.Background(), &pb.ExportRequest{Owner: g.Owner, Endpoint: g.Endpoint, Month: "2026-10"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing node secret=%v", err)
	}
}
