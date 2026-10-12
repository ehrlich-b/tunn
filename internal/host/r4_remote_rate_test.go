package host

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestR4RemoteSharingAdmissionHTTPParity(t *testing.T) {
	for _, kind := range []string{"rate", "capacity"} {
		t.Run(kind, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			ledger, err := metering.New(f.p.mcpOAuth.db, metering.WithOwnerGrantLimit(2))
			if err != nil {
				t.Fatal(err)
			}
			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-node-secret", "review-node-secret"))
			in := &pb.SharingRequest{Operation: "register", Owner: f.tunnel.AccountID, Endpoint: "review-rate", Mode: "private", InitialEmails: []string{"alice@example.com"}}
			wantErr, wantRetry := metering.ErrCapacity, ""
			if kind == "rate" {
				wantErr, wantRetry = metering.ErrSharingRate, "60"
				if _, err := f.p.mcpOAuth.db.Exec(`INSERT INTO sharing_mutation_rate(owner,minute,count) VALUES(?,?,?)`, in.Owner, time.Now().Unix()/60, metering.MaxSharingMutationsPerMinute); err != nil {
					t.Fatal(err)
				}
			} else {
				for i := 0; i < 2; i++ {
					digest := sha256.Sum256([]byte(fmt.Sprint("machine-", i)))
					if _, err := ledger.CreateGrant(ctx, &pb.Grant{Owner: in.Owner, Endpoint: "machine", TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err != nil {
						t.Fatal(err)
					}
				}
			}
			listener := bufconn.Listen(1 << 20)
			defer listener.Close()
			server := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor("review-node-secret")))
			pb.RegisterMeteringServer(server, ledger)
			go func() { _ = server.Serve(listener) }()
			defer server.Stop()
			conn, err := grpc.NewClient("passthrough:///review-rate", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			remote := &metering.Remote{Connection: func() *grpc.ClientConn { return conn }}
			_, localErr := ledger.Sharing(ctx, in)
			_, remoteErr := remote.Sharing(ctx, in)
			if !errors.Is(localErr, wantErr) || !errors.Is(remoteErr, wantErr) {
				t.Fatalf("local=%v remote=%v want=%v", localErr, remoteErr, wantErr)
			}
			_, wireErr := pb.NewMeteringClient(conn).Sharing(ctx, in)
			if status.Code(wireErr) != codes.ResourceExhausted || len(status.Convert(wireErr).Details()) != 1 {
				t.Fatalf("untyped admission RPC: %v", wireErr)
			}
			local, distant := httptest.NewRecorder(), httptest.NewRecorder()
			writeSharingFailure(local, localErr)
			writeSharingFailure(distant, remoteErr)
			if local.Code != 429 || distant.Code != local.Code || local.Header().Get("Retry-After") != wantRetry || distant.Header().Get("Retry-After") != wantRetry || distant.Body.String() != local.Body.String() {
				t.Fatalf("local=%v remote=%v", local.Result(), distant.Result())
			}
			// Admission denial rolls back both registration and sharing rows.
			var n int
			if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM web_resources WHERE endpoint='review-rate'`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("denied registration persisted: %d %v", n, err)
			}
		})
	}
}
