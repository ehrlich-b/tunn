package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc/metadata"
)

func hostFixture(t *testing.T) *TunnelServer {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	cfg := testConfig()
	cfg.HostModeEnabled, cfg.LoginNode, cfg.Domain = true, true, "host.test"
	s := NewTunnelServer(cfg, nil, store.NewAccountStore(db), nil)
	if err := s.EnableHostMode(db); err != nil {
		t.Fatal(err)
	}
	return s
}

func hostRequest(t *testing.T, s *TunnelServer, method, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "https://host.test/api/hosts", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.HandleHosts(w, r)
	return w
}

const fixtureManifest = `{"machine":"gpu-box","tunnels":[{"name":"gpu-http","kind":"http"},{"name":"gpu-mcp","kind":"mcp"}]}`

func TestHostAPIInventoryAndAuth(t *testing.T) {
	s := hostFixture(t)
	token := createTestJWT("owner@example.com", s.cfg.JWTSecret)
	for _, invalid := range []string{"", "garbage", createTestJWT("owner@example.com", "forged")} {
		if got := hostRequest(t, s, http.MethodGet, invalid, "").Code; got != 401 {
			t.Fatalf("invalid token status = %d", got)
		}
	}
	if got := hostRequest(t, s, http.MethodPost, token, fixtureManifest); got.Code != 200 {
		t.Fatalf("register = %d %s", got.Code, got.Body.String())
	}
	account, err := s.hostAccount(token, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.hosts.Seen(account.ID, "gpu-box", "gpu-http", time.Now()); err != nil {
		t.Fatal(err)
	}
	s.tunnels["gpu-http"] = &TunnelConnection{TunnelID: "gpu-http", AccountID: account.ID, HostID: "gpu-box"}
	w := hostRequest(t, s, http.MethodGet, token, "")
	var machines []common.Machine
	if err := json.Unmarshal(w.Body.Bytes(), &machines); err != nil {
		t.Fatal(err)
	}
	if len(machines) != 1 || !machines[0].Online || !machines[0].Tunnels[0].Online || machines[0].Tunnels[0].LastSeen.IsZero() || machines[0].Tunnels[1].URL != "https://gpu-mcp.host.test/mcp" {
		t.Fatalf("inventory = %#v", machines)
	}
	delete(s.tunnels, "gpu-http")
	w = hostRequest(t, s, http.MethodGet, token, "")
	if err := json.Unmarshal(w.Body.Bytes(), &machines); err != nil {
		t.Fatal(err)
	}
	if machines[0].Online || machines[0].Tunnels[0].Online || machines[0].Tunnels[0].LastSeen.IsZero() {
		t.Fatal("disconnect lost last seen or retained online status")
	}
	other := createTestJWT("other@example.com", s.cfg.JWTSecret)
	if w := hostRequest(t, s, http.MethodGet, other, ""); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("inventory leaked: %s", w.Body.String())
	}
	if w := hostRequest(t, s, http.MethodPost, other, fixtureManifest); w.Code != 409 {
		t.Fatalf("reservation stolen: %d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("inventory was cacheable")
	}
}

func TestHostAPIValidation(t *testing.T) {
	s := hostFixture(t)
	token := createTestJWT("owner@example.com", s.cfg.JWTSecret)
	for _, body := range []string{
		`{"machine":"gpu-box","tunnels":[{"name":"api","kind":"http"}]}`,
		`{"machine":"gpu-box","tunnels":[{"name":"gpu-http","kind":"http","target":"secret"}]}`,
		`{"machine":"gpu-box","tunnels":[{"name":"gpu-http","kind":"http"},{"name":"gpu-http","kind":"tcp"}]}`,
		fixtureManifest + ` {}`,
		`{"machine":"bad_machine","tunnels":[]}`,
		strings.Repeat("x", 17000),
	} {
		if w := hostRequest(t, s, http.MethodPost, token, body); w.Code != 400 {
			t.Fatalf("invalid body returned %d", w.Code)
		}
	}
	if w := hostRequest(t, s, http.MethodDelete, token, ""); w.Code != 405 {
		t.Fatal("unexpected method allowed")
	}
	s.cfg.HostModeEnabled = false
	if w := hostRequest(t, s, http.MethodGet, token, ""); w.Code != 404 {
		t.Fatal("disabled feature exposed")
	}
}

type hostFixtureStream struct {
	*mockTunnelStream
	ctx context.Context
}

func (s *hostFixtureStream) Context() context.Context { return s.ctx }

func TestHostStreamReservation(t *testing.T) {
	s := hostFixture(t)
	token := createTestJWT("owner@example.com", s.cfg.JWTSecret)
	if got := hostRequest(t, s, http.MethodPost, token, fixtureManifest); got.Code != 200 {
		t.Fatal(got.Body.String())
	}
	for _, tc := range []struct {
		machine, email string
		allowed        bool
	}{{"gpu-box", "owner@example.com", true}, {"other-box", "owner@example.com", false}, {"gpu-box", "other@example.com", false}, {"", "other@example.com", false}} {
		q := make(chan *pb.TunnelMessage, 1)
		q <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "gpu-http", TargetUrl: "http", TunnelKey: s.cfg.WellKnownKey, AuthToken: createTestJWT(tc.email, s.cfg.JWTSecret), AllowedEmails: []string{tc.email}}}}
		close(q)
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("tunn-host-id", tc.machine))
		stream := &hostFixtureStream{mockTunnelStream: &mockTunnelStream{recvQueue: q}, ctx: ctx}
		err := s.EstablishTunnel(stream)
		if (err == nil) != tc.allowed {
			t.Fatalf("%+v: error %v", tc, err)
		}
		if len(stream.sentMsgs) == 0 || stream.sentMsgs[0].GetRegisterResponse().Success != tc.allowed {
			t.Fatal("incorrect registration response")
		}
	}
	owner, _ := s.hostAccount(token, false)
	list, err := s.hosts.List(owner.ID)
	if err != nil || list[0].Tunnels[0].LastSeen.IsZero() {
		t.Fatal("real stream lifecycle did not record presence")
	}
}

func TestHostModeGate(t *testing.T) {
	s := hostFixture(t)
	for _, change := range []func(){func() { s.cfg.LoginNode = false }, func() { s.cfg.LoginNode = true; s.cfg.PublicMode = true }, func() { s.cfg.PublicMode = false; s.cfg.NodeAddresses = "peer:443" }, func() { s.cfg.NodeAddresses = ""; s.cfg.FlyAppName = "tunn" }, func() { s.cfg.FlyAppName = ""; s.cfg.HostModeEnabled = false }} {
		change()
		if err := s.EnableHostMode(nil); err == nil {
			t.Fatal("unsupported topology or disabled flag admitted")
		}
	}
}

func TestHostStreamCrossNodeReservationGuard(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()
	accounts := store.NewAccountStore(db)
	owner, err := accounts.FindOrCreateByEmails([]string{"owner@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	other, err := accounts.FindOrCreateByEmails([]string{"other@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := store.NewHostStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(owner.ID, common.HostManifest{Machine: "gpu", Tunnels: []common.HostEndpointSpec{{Name: "gpu-ssh", Kind: "tcp"}}}); err != nil {
		t.Fatal(err)
	}
	local := storage.NewLocalStorage(db)
	result, err := local.RegisterTunnel(context.Background(), "gpu-ssh", other.ID, "other-node")
	if err != nil || result.Allowed {
		t.Fatalf("cross-node reservation stolen: %v %v", result, err)
	}
	result, err = local.RegisterTunnel(context.Background(), "gpu-ssh", owner.ID, "other-node")
	if err != nil || !result.Allowed {
		t.Fatalf("owner denied: %v %v", result, err)
	}
}
