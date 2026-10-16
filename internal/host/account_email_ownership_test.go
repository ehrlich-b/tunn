package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestPublishedTunnelOwnerSurvivesPrimarySwitch(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "login-node-RPC"
		}
		t.Run(name, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			p := f.p
			ctx := context.Background()
			if remote {
				p.storage = securityReplicaStorage(t, p.storage.(*storage.LocalStorage))
				p.tunnelServer.storage = p.storage
			}
			p.tunnelServer.sharing = p.meter.(metering.SharingBackend)
			owner, err := p.storage.GetAccountByEmail(ctx, "owner@example.com")
			if err != nil {
				t.Fatal(err)
			}
			oldSession := emailSession(t, p, owner.PrimaryEmail)
			streamCtx, cancel := context.WithCancel(ctx)
			stream := &durableControlStream{ctx: streamCtx, incoming: make(chan *pb.TunnelMessage, 2), outgoing: make(chan *pb.TunnelMessage, 2)}
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{
				TunnelId: "primary-switch", TargetUrl: "http://localhost:8080", AuthToken: oldSession.Value,
				TunnelKey: p.config.WellKnownKey, ExposureVersion: 1, ExposureMode: "private",
			}}}
			done := make(chan error, 1)
			go func() { done <- p.tunnelServer.EstablishTunnel(stream) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("publisher cleanup timed out")
				}
			})
			select {
			case response := <-stream.outgoing:
				if result := response.GetRegisterResponse(); result == nil || !result.Success {
					t.Fatal(response)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("publisher admission timed out")
			}
			tunnel, ok := p.tunnelServer.GetTunnel("primary-switch")
			if !ok || tunnel.AccountID != owner.ID || tunnel.CreatorEmail != owner.PrimaryEmail || tunnel.ResourceID == "" || len(tunnel.AllowedEmails) != 0 {
				t.Fatal("publication lost private owner identity", tunnel)
			}
			go func() {
				for {
					select {
					case <-streamCtx.Done():
						return
					case message := <-stream.outgoing:
						if request := message.GetHttpRequest(); request != nil {
							select {
							case stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_HttpResponse{HttpResponse: &pb.HttpResponse{ConnectionId: request.ConnectionId, StatusCode: 200, Body: []byte("owner access")}}}:
							case <-streamCtx.Done():
								return
							}
						}
					}
				}
			}()
			open := func(cookie *http.Cookie, header string, want int) {
				t.Helper()
				r := httptest.NewRequest("GET", "https://primary-switch.tunn.test/", nil)
				if header == "" {
					r.AddCookie(cookie)
				} else {
					r.Header.Set(header, "Bearer "+cookie.Value)
				}
				w := httptest.NewRecorder()
				p.createHandler().ServeHTTP(w, r)
				if w.Code != want {
					t.Fatalf("%s access: %d, %s", header, w.Code, w.Body)
				}
			}
			open(oldSession, "", 200)
			// Keep a permission watch open across the switch as well as making fresh requests.
			bucket, err := p.storage.GetEmailBucket(ctx, owner.PrimaryEmail)
			if err != nil {
				t.Fatal(err)
			}
			watched, stop := p.watchWebPermission(httptest.NewRequest("GET", "https://primary-switch.tunn.test/events", nil), tunnel, bucket, false)
			defer stop()
			if _, err := p.storage.(storage.AccountEmailStorage).MutateAccountEmail(ctx, owner.ID, "new-primary@example.com", "link"); err != nil {
				t.Fatal(err)
			}
			changed := emailAction(t, f, oldSession, url.Values{"action": {"primary"}, "email": {"new-primary@example.com"}})
			if changed.Code != 303 {
				t.Fatal(changed.Code, changed.Body)
			}
			current := assertAccountsSessionCookie(t, p, changed, "new-primary@example.com")
			for _, email := range []string{owner.PrimaryEmail, "new-primary@example.com"} {
				rejected := emailAction(t, f, current, url.Values{"action": {"remove"}, "email": {email}})
				if rejected.Code != 400 {
					t.Fatal("unsupported email action accepted", rejected.Code, rejected.Body)
				}
			}
			if tunnel.CreatorEmail != owner.PrimaryEmail || tunnel.AccountID != owner.ID {
				t.Fatal("existing publisher identity changed")
			}
			for _, cookie := range []*http.Cookie{oldSession, current} {
				for _, header := range []string{"", "Authorization", "Tunn-Authorization"} {
					open(cookie, header, 200)
				}
			}
			if _, err := p.storage.FindOrCreateByEmails(ctx, []string{"other@example.com"}, "magic_link"); err != nil {
				t.Fatal(err)
			}
			other := emailSession(t, p, "other@example.com")
			for _, header := range []string{"", "Authorization", "Tunn-Authorization"} {
				open(other, header, 403)
			}
			// Neither address can be added to another account after the primary switch.
			for _, email := range []string{owner.PrimaryEmail, "new-primary@example.com"} {
				w := emailAction(t, f, other, url.Values{"action": {"add"}, "email": {email}})
				if w.Code != 409 {
					t.Fatal("email reassigned", email, w.Code, w.Body)
				}
				rebound, err := p.storage.FindOrCreateByEmails(ctx, []string{email}, "magic_link")
				if err != nil || rebound.ID != owner.ID {
					t.Fatal("login changed owners", rebound, err)
				}
			}
			select {
			case <-watched.Context().Done():
				t.Fatal("primary switch revoked an open owner request", context.Cause(watched.Context()))
			case <-time.After(1200 * time.Millisecond):
			}
		})
	}
}
