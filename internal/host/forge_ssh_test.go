package host

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
)

type forgeRegistrationStream struct {
	*mockTunnelStream
	server *TunnelServer
	tunnel *TunnelConnection
}

func (s *forgeRegistrationStream) Recv() (*pb.TunnelMessage, error) {
	msg, err := s.mockTunnelStream.Recv()
	if err == io.EOF {
		s.tunnel, _ = s.server.GetTunnel("forge-ssh")
	}
	return msg, err
}

func TestForgeSSHAccountOnlyRegistrationOnExistingRelay(t *testing.T) {
	local := securityDB(t)
	const owner = "bryan@example.com"
	if _, err := local.FindOrCreateByEmails(context.Background(), []string{owner}, "fixture"); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	server := NewTunnelServer(cfg, nil, local.AccountStore(), local)
	stream := &forgeRegistrationStream{mockTunnelStream: &mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}, server: server}
	stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{
		TunnelId: "forge-ssh", TargetUrl: "tcp", EndpointProtocol: "tcp",
		TunnelKey: cfg.WellKnownKey, AuthToken: createTestJWT(owner, cfg.JWTSecret),
		CreatorEmail: "forged@example.com", AllowedEmails: []string{owner},
		Capabilities: []string{common.CapabilityConnectionStreamV1},
	}}}
	close(stream.recvQueue)
	if err := server.EstablishTunnel(stream); err != nil {
		t.Fatal(err)
	}
	if stream.tunnel == nil || stream.tunnel.CreatorEmail != owner || len(stream.tunnel.accessTokenDigest()) != 0 || len(stream.tunnel.AllowedEmails) != 1 || stream.tunnel.AllowedEmails[0] != owner {
		t.Fatalf("account-only registration was not preserved: %+v", stream.tunnel)
	}
	if response := stream.sentMsgs[0].GetRegisterResponse(); response == nil || !response.Success {
		t.Fatalf("registration response = %+v", response)
	}
}

// Exercise the unchanged relay policy with the account-only publisher's wire
// shape: an owner allow-list and no endpoint capability digest.
func TestForgeSSHPrivateTCPAccountPolicy(t *testing.T) {
	for _, caller := range []string{"owner", "other", "anonymous", "expired", "forged", "endpoint-token", "grant", "login-link"} {
		t.Run(caller, func(t *testing.T) {
			p, tunnel, ledger, stream := meteringRelay(t, true, "SSH-2.0-forge\r\n")
			tunnel.EndpointProtocol = "tcp"
			tunnel.AllowedEmails = []string{tunnel.CreatorEmail}
			tunnel.Capabilities[common.CapabilityConnectionStreamV1] = true
			var token string
			want := http.StatusUnauthorized
			switch caller {
			case "owner":
				token, want = relayJWT(t, p, tunnel.CreatorEmail), http.StatusOK
			case "other":
				token, want = relayJWT(t, p, "other@example.com"), http.StatusForbidden
			case "expired", "forged", "login-link":
				claims := jwt.MapClaims{"email": tunnel.CreatorEmail, "exp": time.Now().Add(time.Hour).Unix()}
				key := p.getJWTSigningKey()
				if caller == "expired" {
					claims["exp"] = time.Now().Add(-time.Minute).Unix()
				}
				if caller == "forged" {
					key = []byte("wrong-fixture-key")
				}
				if caller == "login-link" {
					claims["type"] = "magic_link"
				}
				var err error
				token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
				if err != nil {
					t.Fatal(err)
				}
			case "endpoint-token":
				token = "tunn_ep_stale-capability"
			case "grant":
				_, token = relayGrant(t, ledger, 0, 0)
				want = http.StatusForbidden
			}
			r := relayRequest(token, "SSH-2.0-laptop\r\n")
			r.Method, r.URL.Path = http.MethodConnect, common.TCPConnectPath
			r.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("%s status = %d, want %d: %s", caller, w.Code, want, w.Body)
			}
			stream.mu.Lock()
			defer stream.mu.Unlock()
			if want != http.StatusOK && len(stream.sentMsgs) != 0 {
				t.Fatal("denied identity reached the publisher")
			}
			if want == http.StatusOK && w.Body.String() != "SSH-2.0-forge\r\n" {
				t.Fatalf("SSH bytes = %q", w.Body.String())
			}
			for _, msg := range stream.sentMsgs {
				if data := msg.GetConnectionData(); data != nil && string(data.Data) != "SSH-2.0-laptop\r\n" {
					t.Fatalf("platform credentials leaked into the SSH byte stream: %q", data.Data)
				}
			}
		})
	}
}

func TestForgeSSHPrivateTCPGrantRevocation(t *testing.T) {
	p, tunnel, _, stream := meteringRelay(t, true, "SSH-2.0-forge\r\n")
	tunnel.EndpointProtocol = "tcp"
	tunnel.Capabilities[common.CapabilityConnectionStreamV1] = true
	// The fixture starts with an explicit grant to Alice plus the owner.
	token := relayJWT(t, p, "alice@example.com")
	connect := func(want int) {
		t.Helper()
		r := relayRequest(token, "SSH-2.0-laptop\r\n")
		r.Method, r.URL.Path = http.MethodConnect, common.TCPConnectPath
		r.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("account grant status = %d, want %d: %s", w.Code, want, w.Body)
		}
	}
	connect(http.StatusOK)
	stream.mu.Lock()
	before := len(stream.sentMsgs)
	stream.mu.Unlock()
	// A re-published owner-only registration omits Alice's email.
	tunnel.AllowedEmails = []string{tunnel.CreatorEmail}
	connect(http.StatusForbidden)
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if len(stream.sentMsgs) != before {
		t.Fatal("revoked account grant reached the publisher")
	}
}
