package host

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

func TestAuditOwnerPageExportsAndDirectIDs(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprint(remote), func(t *testing.T) {
			f := newWebInspectorFixture(t, 0, 0)
			f.seed(t)
			other := f.accountCookie(t, "other@example.com")
			owner, _ := f.local.GetAccountByEmail(context.Background(), "owner@example.com")
			outsider, _ := f.local.GetAccountByEmail(context.Background(), "other@example.com")
			now := time.Now().UTC()
			for i := 0; i < 62; i++ {
				account, endpoint := owner.ID, "owner-endpoint"
				if i == 61 {
					account, endpoint = outsider.ID, "PRIVATE_OTHER_ENDPOINT"
				}
				e := &pb.Event{RequestId: fmt.Sprintf("%032x", i), Owner: account, Endpoint: endpoint, StartedAt: now.Add(-time.Hour).UnixMilli(), Finished: true, Status: 201, RequestBytes: 123, ResponseBytes: 456, DurationMs: 78, Caller: "PRIVATE_CALLER", GrantId: "PRIVATE_GRANT"}
				data, _ := json.Marshal(e)
				if _, err := f.db.Exec(`INSERT INTO meter_events(id,owner,endpoint,month,finished,data) VALUES(?,?,?,?,?,?)`, e.RequestId, account, endpoint, now.Format("2006-01"), true, data); err != nil {
					t.Fatal(err)
				}
			}
			if remote {
				ledger := f.p.meter.(*metering.Store)
				l := bufconn.Listen(1 << 20)
				defer l.Close()
				s := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor("audit-test")))
				pb.RegisterMeteringServer(s, ledger)
				go func() { _ = s.Serve(l) }()
				defer s.Stop()
				conn, err := grpc.NewClient("passthrough:///audit-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return l.Dial() }), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
					return invoke(metadata.AppendToOutgoingContext(ctx, "x-node-secret", "audit-test"), method, req, reply, cc, opts...)
				}))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				f.p.meter = &metering.Remote{Connection: func() *grpc.ClientConn { return conn }}
			}
			for _, path := range []string{"/account/audit", "/account/audit.csv", "/account/audit.json"} {
				w := f.call("GET", path, nil, f.cookie, nil)
				if w.Code != 200 {
					t.Fatalf("%s %d %s", path, w.Code, w.Body)
				}
				for _, secret := range []string{"PRIVATE_OTHER_ENDPOINT", "PRIVATE_CALLER", "PRIVATE_GRANT", "QUERY_SENTINEL", "BODY_PAYLOAD_SENTINEL"} {
					if strings.Contains(w.Body.String(), secret) {
						t.Fatalf("%s leaked %s", path, secret)
					}
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal(w.Header())
				}
			}
			for _, path := range []string{"/account/audit?endpoint=owner-endpoint", "/account/audit.csv?endpoint=owner-endpoint", "/account/audit.json?endpoint=owner-endpoint"} {
				w := f.call("GET", path, nil, other, nil)
				if w.Code != 200 || strings.Contains(w.Body.String(), "owner-endpoint</span>") || strings.Contains(w.Body.String(), `"endpoint":"owner-endpoint"`) || strings.Contains(w.Body.String(), ",owner-endpoint,") {
					t.Fatalf("cross account %s: %d %s", path, w.Code, w.Body)
				}
			}
			id := fmt.Sprintf("%032x", 1)
			for _, path := range []string{"/api/account/audit/" + id, "/account/audit?request_id=" + id, "/account/audit.csv?request_id=" + id, "/account/audit.json?request_id=" + id} {
				if w := f.call("GET", path, nil, other, nil); w.Code != 404 {
					t.Fatalf("direct %s: %d %s", path, w.Code, w.Body)
				}
			}
			w := f.call("GET", "/api/account/audit/"+id, nil, f.cookie, nil)
			var out struct{ Requests []auditRow }
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Requests) != 1 {
				t.Fatal(w.Body, err)
			}
			row := out.Requests[0]
			if row.Path != nil || row.ClientIP != nil || row.UserAgentFamily != nil || row.Status != 201 || row.BytesIn != 123 || row.BytesOut != 456 || row.DurationMS != 78 {
				t.Fatal(row)
			}
			w = f.call("GET", "/account/audit.csv?status=2&endpoint=owner-endpoint", nil, f.cookie, nil)
			records, err := csv.NewReader(w.Body).ReadAll()
			if err != nil || len(records) != 62 {
				t.Fatal(len(records), err)
			}
			w = f.call("GET", "/account/audit?endpoint=owner-endpoint", nil, f.cookie, nil)
			html := w.Body.String()
			start := strings.Index(html, `href="/account/audit?cursor=`)
			if start < 0 {
				t.Fatal("missing next page")
			}
			end := strings.Index(html[start+6:], `"`)
			next := strings.ReplaceAll(html[start+6:start+6+end], "&amp;", "&")
			w = f.call("GET", next, nil, f.cookie, nil)
			if w.Code != 200 || strings.Count(w.Body.String(), `class="endpoint"`) != 11 {
				t.Fatal("second page", next, w.Code, w.Body)
			}
			for _, path := range []string{"/account/audit?status=6", "/account/audit?cursor=bad", "/account/audit?since=no", "/account/audit?endpoint=%3Cscript%3E"} {
				if w = f.call("GET", path, nil, f.cookie, nil); w.Code != 400 {
					t.Fatal(path, w.Code)
				}
			}
			if w = f.call("GET", "/account/audit", nil, nil, nil); w.Code != 302 {
				t.Fatal(w.Code)
			}
			if w = f.call("GET", "/account", nil, f.cookie, nil); !strings.Contains(w.Body.String(), `href="/account/audit"`) {
				t.Fatal("account link missing")
			}
		})
	}
}

func TestAuditRetentionCSRFAndAuthorityFailure(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	req := httptest.NewRequest("GET", "https://tunn.test/account/audit", nil)
	req.AddCookie(f.cookie)
	csrf, err := f.p.createCSRFToken(req, "audit-retention")
	if err != nil {
		t.Fatal(err)
	}
	post := func(days, token, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://tunn.test/account/audit", strings.NewReader(url.Values{"days": {days}, "csrf_token": {token}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.AddCookie(f.cookie)
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		return w
	}
	for _, v := range []struct {
		days, token, origin string
		want                int
	}{{"7", "", "https://tunn.test", 403}, {"7", csrf, "https://evil.test", 403}, {"8", csrf, "https://tunn.test", 400}, {"7", csrf, "https://tunn.test", 303}} {
		if w := post(v.days, v.token, v.origin); w.Code != v.want {
			t.Fatal(v, w.Code, w.Body)
		}
	}
	a, _ := f.local.GetAccountByEmail(context.Background(), "owner@example.com")
	out, err := f.p.meter.(metering.AuditBackend).Audit(context.Background(), &pb.AuditRequest{Owner: a.ID, Operation: "list"})
	if err != nil || out.RetentionDays != 7 {
		t.Fatal(out, err)
	}
	f.p.meter = &metering.Remote{Connection: func() *grpc.ClientConn { return nil }}
	for _, path := range []string{"/account/audit", "/account/audit.csv", "/account/audit.json"} {
		if w := f.call("GET", path, nil, f.cookie, nil); w.Code != 503 {
			t.Fatal(path, w.Code)
		}
	}
	if w := post("30", csrf, "https://tunn.test"); w.Code != 503 {
		t.Fatal(w.Code)
	}
	if w := f.call(http.MethodDelete, "/account/audit", nil, f.cookie, nil); w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestAuditRetentionFollowsVerifiedAccountMerge(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	ctx := context.Background()
	a, _ := f.local.GetAccountByEmail(ctx, "owner@example.com")
	b, err := f.local.FindOrCreateByEmails(ctx, []string{"merge@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	backend := f.p.meter.(metering.AuditBackend)
	for _, in := range []*pb.AuditRequest{{Owner: a.ID, Operation: "retention", RetentionDays: 30}, {Owner: b.ID, Operation: "retention", RetentionDays: 7}} {
		if _, err = backend.Audit(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	merged, err := f.local.FindOrCreateByEmails(ctx, []string{"owner@example.com", "merge@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	out, err := backend.Audit(ctx, &pb.AuditRequest{Owner: merged.ID, Operation: "list"})
	if err != nil || out.RetentionDays != 7 {
		t.Fatal(out, err)
	}
	var n int
	if err = f.db.QueryRow(`SELECT count(*) FROM meter_audit_retention`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
}

// A full retained ledger can exceed gRPC's default response envelope even
// though the public export omits caller and grant metadata.
type auditLargeResponseServer struct {
	pb.UnimplementedMeteringServer
	response *pb.AuditResponse
}

func (s *auditLargeResponseServer) Audit(context.Context, *pb.AuditRequest) (*pb.AuditResponse, error) {
	return s.response, nil
}

func TestAuditRemoteExportBeyondDefaultGRPCEnvelope(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	owner, err := f.local.GetAccountByEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	out := &pb.AuditResponse{}
	privateCaller := "PRIVATE_CALLER_" + strings.Repeat("c", 240)
	for i := 0; i < metering.MaxEvents; i++ {
		out.Events = append(out.Events, &pb.Event{RequestId: fmt.Sprintf("%032x", i), Owner: owner.ID, Endpoint: strings.Repeat("a", 63), Caller: privateCaller, AuthMethod: strings.Repeat("m", 32), Reason: strings.Repeat("r", 64), GrantId: strings.Repeat("g", 36), Month: time.Now().UTC().Format("2006-01"), StartedAt: time.Now().UnixMilli(), Finished: true, Status: 200})
	}
	if size := proto.Size(out); size <= 4<<20 {
		t.Fatalf("fixture must exceed default receive envelope: %d", size)
	}
	l := bufconn.Listen(1 << 20)
	defer l.Close()
	server := grpc.NewServer(grpc.UnaryInterceptor(nodeSecretInterceptor("large-audit-test")))
	pb.RegisterMeteringServer(server, &auditLargeResponseServer{response: out})
	go func() { _ = server.Serve(l) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///large-audit-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return l.Dial() }), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoke(metadata.AppendToOutgoingContext(ctx, "x-node-secret", "large-audit-test"), method, req, reply, cc, opts...)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	remote := &metering.Remote{Connection: func() *grpc.ClientConn { return conn }}
	got, err := remote.Audit(context.Background(), &pb.AuditRequest{Owner: owner.ID, Operation: "list", Limit: metering.MaxEvents})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != metering.MaxEvents {
		t.Fatal("truncated internal export", len(got.Events))
	}
	f.p.meter = remote
	w := f.call("GET", "/account/audit.json", nil, f.cookie, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var exported struct{ Requests []auditRow }
	if err = json.Unmarshal(w.Body.Bytes(), &exported); err != nil || len(exported.Requests) != metering.MaxEvents {
		t.Fatal("truncated public export", len(exported.Requests), err)
	}
	if strings.Contains(w.Body.String(), privateCaller) {
		t.Fatal("private metadata leaked")
	}
}
