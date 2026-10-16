package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/sshfront"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"golang.org/x/crypto/ssh"
)

func reviewDatabaseRelay(t *testing.T) (*ProxyServer, *sql.DB, sshfront.Identity) {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	st := storage.NewLocalStorage(db)
	cfg := &config.Config{Domain: "tunn.test", PublicAddr: "tunn.test", LoginNode: true, JWTSecret: "review-test-secret", WellKnownKey: "creation"}
	if _, err := st.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "test"); err != nil {
		t.Fatal(err)
	}
	keys, err := sshfront.NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	pub := string(ssh.MarshalAuthorizedKey(sshSigner(t).PublicKey()))
	key, err := keys.Add(context.Background(), "owner@example.com", pub)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := metering.New(db)
	if err != nil {
		t.Fatal(err)
	}
	p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, st.AccountStore(), st), storage: st, meter: ledger, sshKeys: keys, quotaCache: NewQuotaCache(time.Minute), usageBuffer: NewUsageBuffer(), tunnelCache: map[string]string{}}
	return p, db, sshfront.Identity{Fingerprint: key.Fingerprint, PublicKey: pub, Email: "owner@example.com", IP: "127.0.0.1"}
}

func reviewPublish(t *testing.T, p *ProxyServer, allowed []string) func() {
	return reviewPublishNamed(t, p, "owner@example.com", "forge-ssh", allowed)
}

func reviewPublishNamed(t *testing.T, p *ProxyServer, owner, name string, allowed []string, dialers ...func(context.Context, string, string) (net.Conn, error)) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 32), outgoing: make(chan *pb.TunnelMessage, 32)}
	token, err := p.generateJWT(owner)
	if err != nil {
		t.Fatal(err)
	}
	stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: name, TargetUrl: "tcp", EndpointProtocol: "tcp", AuthToken: token, TunnelKey: p.config.WellKnownKey, AllowedEmails: allowed, Capabilities: []string{common.CapabilityConnectionStreamV1}}}}
	hostDone := make(chan struct{})
	go func() { defer close(hostDone); _ = p.tunnelServer.EstablishTunnel(stream) }()
	select {
	case m := <-stream.outgoing:
		if !m.GetRegisterResponse().Success {
			t.Fatal(m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("registration timeout")
	}
	publisher := &client.ServeClient{TargetURL: "review-echo.invalid", EndpointProtocol: "tcp", DialContext: func(context.Context, string, string) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() { defer remote.Close(); io.Copy(remote, remote) }()
		return local, nil
	}}
	if len(dialers) > 0 {
		publisher.DialContext = dialers[0]
	}
	clientDone := make(chan struct{})
	go func() { defer close(clientDone); _ = publisher.ServeMessages(ctx, reviewPublisherStream{stream}) }()
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); <-hostDone; <-clientDone }) }
	t.Cleanup(stop)
	return stop
}

type reviewPublisherStream struct{ *durableControlStream }

func (s reviewPublisherStream) Send(m *pb.TunnelMessage) error {
	select {
	case s.incoming <- m:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s reviewPublisherStream) Recv() (*pb.TunnelMessage, error) {
	select {
	case m := <-s.outgoing:
		return m, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func reviewEcho(c net.Conn) error {
	if _, err := c.Write([]byte("ok")); err != nil {
		return err
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if string(b) != "ok" {
		return fmt.Errorf("bad echo %q", b)
	}
	return nil
}

// A single held pool lease models a normal login-node database stall. The actual
// LocalStorage implementation executes the timed call, not a mock lookup.
type reviewPoolStall struct {
	storage.Storage
	db                 *sql.DB
	armed              atomic.Bool
	held               chan *sql.Conn
	checkCtx           chan context.Context
	ignoreCancellation bool
}

func (s *reviewPoolStall) GetAccount(ctx context.Context, id string) (*storage.Account, error) {
	if s.armed.CompareAndSwap(true, false) {
		lease, err := s.db.Conn(ctx)
		if err != nil {
			return nil, err
		}
		s.held <- lease
		s.checkCtx <- ctx
	}
	if s.ignoreCancellation {
		ctx = context.WithoutCancel(ctx)
	}
	return s.Storage.GetAccount(ctx, id)
}

func TestReviewRevocationHasFiveSecondDeadline(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		name := "context-aware storage"
		if ignore {
			name = "storage ignores cancellation"
		}
		t.Run(name, func(t *testing.T) { reviewRevocationDeadline(t, ignore) })
	}
}

func reviewRevocationDeadline(t *testing.T, ignore bool) {
	p, db, id := reviewDatabaseRelay(t)
	reviewPublish(t, p, []string{"owner@example.com"})
	stalled := &reviewPoolStall{Storage: p.storage, db: db, held: make(chan *sql.Conn, 1), checkCtx: make(chan context.Context, 1), ignoreCancellation: ignore}
	p.storage = stalled
	stream, err := p.sshConnect(context.Background(), id, "forge-ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := reviewEcho(stream); err != nil {
		t.Fatal(err)
	}
	stalled.armed.Store(true)
	var held *sql.Conn
	select {
	case held = <-stalled.held:
	case <-time.After(3 * time.Second):
		t.Fatal("watcher did not enter account lookup")
	}
	var release sync.Once
	closeLease := func() { release.Do(func() { held.Close() }) }
	defer closeLease()
	checkCtx := <-stalled.checkCtx
	// The revocation itself commits successfully on the held connection.
	if _, err := held.ExecContext(context.Background(), "DELETE FROM ssh_keys WHERE fingerprint=?", id.Fingerprint); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	result := make(chan error, 1)
	go func() { _, err := stream.Read(make([]byte, 2)); result <- err }()
	select {
	case err = <-result:
	case <-time.After(5200 * time.Millisecond):
		err = nil
	}
	elapsed := time.Since(start)
	t.Logf("after committed revocation: elapsed=%s authority-context=%v transport-close=%v", elapsed, checkCtx.Err(), err)
	closeLease()
	if err == nil {
		t.Fatal("revoked key retained open transport beyond five seconds while the authority context was expired")
	}
}

func TestReviewAnonymousTargetOracle(t *testing.T) {
	p, client, _ := sshRelay(t, false)
	reviewPublish(t, p, []string{"owner@example.com"})
	for _, port := range []string{"22", "80"} {
		_, online := client.Dial("tcp", "forge-ssh:"+port)
		_, absent := client.Dial("tcp", "absent-review-target:"+port)
		if online == nil || absent == nil {
			t.Fatal("unexpected admission", online, absent)
		}
		t.Logf("unlinked key port %s: existing=%v absent=%v", port, online, absent)
		if online.Error() != absent.Error() {
			t.Error("unlinked key can distinguish an online private TCP target from an absent target")
		}
	}
}

func TestReviewCannotRegisterAnotherPersonsKey(t *testing.T) {
	p, _, _ := sshRelay(t, true)
	victim := sshSigner(t)
	pub := string(ssh.MarshalAuthorizedKey(victim.PublicKey()))
	body, _ := json.Marshal(map[string]string{"public_key": pub})
	token, err := p.generateJWT("owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://tunn.test/api/ssh/keys", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	p.handleSSHKeys(w, r)
	challenge, err := p.sshKeys.BeginLink(context.Background(), pub, "victim@example.com")
	if err != nil {
		t.Fatal(err)
	}
	err = p.sshKeys.CompleteLink(context.Background(), challenge)
	t.Logf("account key-add status=%d victim-confirmation=%v", w.Code, err)
	if w.Code == http.StatusOK && err != nil {
		t.Fatal("authenticated account squatted a foreign public key without proof of possession, blocking its actual owner's enrollment")
	}
}

func TestReviewJumpNamesAndUnconfirmedAdmission(t *testing.T) {
	p, _, _ := sshRelay(t, true)
	reviewPublish(t, p, []string{"alice@example.com"})
	alice := sshSigner(t)
	pub := string(ssh.MarshalAuthorizedKey(alice.PublicKey()))
	key, _ := sshfront.ParseKey(pub)
	id := sshfront.Identity{Fingerprint: key.Fingerprint, PublicKey: pub, IP: "127.0.0.1"}
	link, err := p.sshKeys.BeginLink(context.Background(), pub, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if stream, err := p.sshConnect(context.Background(), id, "forge-ssh"); err == nil {
		stream.Close()
		t.Fatal("pending unconfirmed key admitted")
	}
	if _, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"alice@example.com"}, "magic_link"); err != nil {
		t.Fatal(err)
	}
	if err := p.sshKeys.CompleteLink(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	id.Email = "alice@example.com"
	stream, err := p.sshConnect(context.Background(), id, "forge-ssh")
	if err != nil {
		t.Fatal(err)
	}
	if err := reviewEcho(stream); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	if _, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"bob@example.com"}, "test"); err != nil {
		t.Fatal(err)
	}
	reviewPublishNamed(t, p, "bob@example.com", "bob-target", []string{"bob@example.com"})
	for _, name := range []string{"bob-target", "FORGE-SSH", "Forge-ssh", "fоrge-ssh", "ｆorge-ssh", "forge-ssh.tunn.test", "forge-ssh.", "xn--frge-ssh-7jg", "other-publisher"} {
		if c, err := p.sshConnect(context.Background(), id, name); err == nil {
			c.Close()
			t.Fatalf("target variant admitted: %q", name)
		}
	}
}

func TestReviewOuterAgentAndUnixForwardingDenied(t *testing.T) {
	_, c, _ := sshRelay(t, true)
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	accepted, err := session.SendRequest("auth-agent-req@openssh.com", true, nil)
	if err != nil || accepted {
		t.Fatal("outer agent request", accepted, err)
	}
	if ch, _, err := c.OpenChannel("auth-agent@openssh.com", nil); err == nil {
		ch.Close()
		t.Fatal("outer agent channel accepted")
	}
	if ch, _, err := c.OpenChannel("direct-streamlocal@openssh.com", nil); err == nil {
		ch.Close()
		t.Fatal("outer unix forwarding accepted")
	}
}

func TestReviewInnerSSHTrustAndAuthentication(t *testing.T) {
	p, c, _ := sshRelay(t, true)
	originKey := sshSigner(t)
	originUser := sshSigner(t)
	originConfig := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "deploy" || !bytes.Equal(key.Marshal(), originUser.PublicKey().Marshal()) {
			return nil, fmt.Errorf("origin authorization denied")
		}
		return nil, nil
	}}
	originConfig.AddHostKey(originKey)
	reviewPublishNamed(t, p, "owner@example.com", "forge-ssh", []string{"owner@example.com"}, func(context.Context, string, string) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer remote.Close()
			origin, channels, requests, err := ssh.NewServerConn(remote, originConfig)
			if err != nil {
				return
			}
			defer origin.Close()
			go ssh.DiscardRequests(requests)
			for channel := range channels {
				if channel.ChannelType() != "session" {
					channel.Reject(ssh.Prohibited, "session only")
					continue
				}
				ch, rs, err := channel.Accept()
				if err != nil {
					continue
				}
				go func() {
					defer ch.Close()
					for req := range rs {
						if req.Type != "exec" {
							req.Reply(false, nil)
							continue
						}
						req.Reply(true, nil)
						io.WriteString(ch, "origin-ok")
						ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						return
					}
				}()
			}
		}()
		return local, nil
	})
	for _, tc := range []struct {
		name, user string
		trusted    ssh.PublicKey
		signer     ssh.Signer
		succeeds   bool
	}{
		{"original host key and authorized origin user", "deploy", originKey.PublicKey(), originUser, true},
		{"substituted origin pin", "deploy", sshSigner(t).PublicKey(), originUser, false},
		{"relay grant without origin key", "deploy", originKey.PublicKey(), sshSigner(t), false},
		{"unauthorized OS user", "root", originKey.PublicKey(), originUser, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream, err := c.Dial("tcp", "forge-ssh:22")
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			conn, channels, requests, err := ssh.NewClientConn(stream, "forge-ssh", &ssh.ClientConfig{User: tc.user, Auth: []ssh.AuthMethod{ssh.PublicKeys(tc.signer)}, HostKeyCallback: ssh.FixedHostKey(tc.trusted)})
			if !tc.succeeds {
				if err == nil {
					conn.Close()
					t.Fatal("inner SSH trust/authentication boundary bypassed")
				}
				t.Logf("origin rejected inner connection: %v", err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			inner := ssh.NewClient(conn, channels, requests)
			defer inner.Close()
			session, err := inner.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			output, err := session.Output("fixture-command")
			if err != nil || string(output) != "origin-ok" {
				t.Fatal(string(output), err)
			}
		})
	}
}

func TestReviewLivePersonRevokeClosesStream(t *testing.T) {
	p, _, _ := reviewDatabaseRelay(t)
	alicePub := string(ssh.MarshalAuthorizedKey(sshSigner(t).PublicKey()))
	if _, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"alice@example.com"}, "test"); err != nil {
		t.Fatal(err)
	}
	key, err := p.sshKeys.Add(context.Background(), "alice@example.com", alicePub)
	if err != nil {
		t.Fatal(err)
	}
	id := sshfront.Identity{Fingerprint: key.Fingerprint, PublicKey: alicePub, Email: "alice@example.com", IP: "127.0.0.1"}
	stop := reviewPublish(t, p, []string{"alice@example.com"})
	stream, err := p.sshConnect(context.Background(), id, "forge-ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := reviewEcho(stream); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	stop()
	result := make(chan error, 1)
	go func() { _, err := stream.Read(make([]byte, 1)); result <- err }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("revoked publication stream readable")
		}
		t.Logf("person revocation by stopping publication: %s", time.Since(start))
	case <-time.After(5 * time.Second):
		t.Fatal("stopped publication retained stream")
	}
	reviewPublish(t, p, []string{"owner@example.com"})
	if stream, err := p.sshConnect(context.Background(), id, "forge-ssh"); err == nil {
		stream.Close()
		t.Fatal("removed recipient admitted after publisher restart")
	}
}
