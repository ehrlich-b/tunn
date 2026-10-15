package host

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/sshfront"
	"github.com/ehrlich-b/tunn/internal/storage"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"golang.org/x/crypto/ssh"
)

func TestAccountEmailRemovalPreservesCredentialOwnership(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "login-node-RPC"
		}
		t.Run(name, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			p := f.p
			ctx := context.Background()
			local := p.storage.(*storage.LocalStorage)
			if remote {
				p.storage = securityReplicaStorage(t, local)
				p.tunnelServer.storage = p.storage
			}
			owner, err := local.GetAccountByEmail(ctx, "owner@example.com")
			if err != nil {
				t.Fatal(err)
			}
			p.sshKeys, err = sshfront.NewRegistry(p.devices.db)
			if err != nil {
				t.Fatal(err)
			}
			signer := sshSigner(t)
			pub := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
			key, err := p.sshKeys.Add(ctx, owner.PrimaryEmail, pub)
			if err != nil {
				t.Fatal(err)
			}
			id := sshfront.Identity{Fingerprint: key.Fingerprint, PublicKey: pub, Email: owner.PrimaryEmail, AccountID: owner.ID}
			pendingSigner := sshSigner(t)
			pendingPub := string(ssh.MarshalAuthorizedKey(pendingSigner.PublicKey()))
			proof, err := p.sshKeys.BeginProof(ctx, pendingPub, owner.PrimaryEmail, owner.ID)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := pendingSigner.Sign(rand.Reader, sshfront.ProofMessage(owner.PrimaryEmail, proof))
			if err != nil {
				t.Fatal(err)
			}
			link, err := p.sshKeys.BeginLink(ctx, pendingPub, owner.PrimaryEmail)
			if err != nil {
				t.Fatal(err)
			}
			token := durableLogin(t, p)
			originalAccess := token.Access
			// An authorized but unredeemed code is also permanently bound to A.
			code, err := local.CreateDeviceCode(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := local.AuthorizeDeviceCode(ctx, code.Code, owner.PrimaryEmail); err != nil || !ok {
				t.Fatal(ok, err)
			}
			oldSession := emailSession(t, p, owner.PrimaryEmail)
			authority := p.storage.(storage.AccountEmailStorage)
			if _, err = authority.MutateAccountEmail(ctx, owner.ID, "survivor@example.com", "link"); err != nil {
				t.Fatal(err)
			}
			changed := emailAction(t, f, oldSession, url.Values{"action": {"primary"}, "email": {"survivor@example.com"}})
			if changed.Code != 303 {
				t.Fatal(changed.Code, changed.Body)
			}
			sessionA := assertAccountsSessionCookie(t, p, changed, "survivor@example.com")
			// Exercise HTTP refresh after primary change, removal, and reassignment.
			refresh := func(request string) {
				t.Helper()
				w, next := durableRefresh(p, token.Refresh, strings.Repeat(request, 32))
				if w.Code != 200 {
					t.Fatal("refresh", w.Code, w.Body)
				}
				if signedAccountID(next.Access) != owner.ID {
					t.Fatal("refresh changed account UUID")
				}
				email, err := p.tunnelServer.validatePublisherToken(next.Access)
				if err != nil || email != "survivor@example.com" {
					t.Fatal(email, err)
				}
				token = next
			}
			refresh("a")
			beforeRemoval := originalAccess
			removed := emailAction(t, f, sessionA, url.Values{"action": {"remove"}, "email": {owner.PrimaryEmail}})
			if removed.Code != 303 {
				t.Fatal(removed.Code, removed.Body)
			}
			refresh("b")
			other, err := local.FindOrCreateByEmails(ctx, []string{owner.PrimaryEmail}, "magic_link")
			if err != nil || other.ID == owner.ID {
				t.Fatal(other, err)
			}
			sessionB := emailSession(t, p, owner.PrimaryEmail)
			refresh("c")
			// Recovery loads the same UUID, and the pre-removal lease never follows B.
			recovery, next := durableRefresh(p, token.Refresh, strings.Repeat("d", 32))
			if recovery.Code != 200 {
				t.Fatal(recovery.Code, recovery.Body)
			}
			retry, recovered := durableRefresh(p, token.Refresh, strings.Repeat("d", 32))
			if retry.Code != 200 || recovered.Refresh != next.Refresh || signedAccountID(recovered.Access) != owner.ID {
				t.Fatal(retry.Code, retry.Body)
			}
			token = next
			visitor := httptest.NewRequest("GET", "https://tools.tunn.test/", nil)
			visitor.Header.Set("Authorization", "Bearer "+originalAccess)
			if email, _, _, ok := p.getAuthFromTunnelBearer(visitor, f.tunnel); !ok || email != "survivor@example.com" {
				t.Fatal("device visitor rebound", email, ok)
			}
			email, err := p.tunnelServer.validatePublisherToken(beforeRemoval)
			if err != nil || email != "survivor@example.com" {
				t.Fatal("old lease rebound", email, err)
			}
			lease := &publisherDeviceLease{accountID: owner.ID, device: token.Device, expiry: time.Now().Add(time.Minute)}
			if err := lease.renew(token.Access, p.getJWTSigningKey(), time.Now()); err != nil {
				t.Fatal("UUID lease renewal", err)
			}
			exchange := f.request("GET", "https://tunn.test/api/device/token?durable=1&code="+url.QueryEscape(code.Code), "", "", "", nil)
			var issued durableTokenFixture
			if err := json.Unmarshal(exchange.Body.Bytes(), &issued); err != nil || exchange.Code != 200 || signedAccountID(issued.Access) != owner.ID {
				t.Fatal("pending code rebound", exchange.Code, exchange.Body, err)
			}

			// Real publisher admission resolves the signed UUID even though the original
			// mailbox now resolves to B in both local and RPC account storage.
			streamCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			stream := &durableControlStream{ctx: streamCtx, incoming: make(chan *pb.TunnelMessage, 2), outgoing: make(chan *pb.TunnelMessage, 2)}
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "email-owner", TargetUrl: "http://localhost:8080", AuthToken: originalAccess, TunnelKey: p.config.WellKnownKey, Capabilities: []string{deviceReauthCapability}}}}
			done := make(chan error, 1)
			go func() { done <- p.tunnelServer.EstablishTunnel(stream) }()
			select {
			case response := <-stream.outgoing:
				if result := response.GetRegisterResponse(); result == nil || !result.Success {
					t.Fatal(response)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("publisher admission timed out")
			}
			tunnel, ok := p.tunnelServer.GetTunnel("email-owner")
			if !ok || tunnel.AccountID != owner.ID {
				t.Fatal("publisher transferred", tunnel)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("publisher cleanup timed out")
			}

			for _, header := range []string{"Authorization", "Tunn-Authorization"} {
				r := httptest.NewRequest("GET", "https://tunn.test/api/sharing", nil)
				r.Header.Set(header, "Bearer "+oldSession.Value)
				if email, _, _, ok := p.getAuthFromTunnelBearer(r, &TunnelConnection{}); ok {
					t.Fatal("stale bearer accepted", header, email)
				}
				if account := p.sharingOwner(httptest.NewRecorder(), r, false); account != nil {
					t.Fatal("stale bearer reached owner", account)
				}
				// A current UUID-bound session still authenticates through either header.
				r.Header.Set(header, "Bearer "+sessionA.Value)
				if account := p.sharingOwner(httptest.NewRecorder(), r, false); account == nil || account.ID != owner.ID {
					t.Fatal("live owner session rejected", account)
				}
			}
			r := httptest.NewRequest("GET", "https://tunn.test/account", nil)
			r.AddCookie(oldSession)
			if _, ok := p.getAuthFromCookie(r); ok {
				t.Fatal("stale cookie accepted")
			}
			r.Header.Set("Authorization", "Bearer "+oldSession.Value)
			w := httptest.NewRecorder()
			p.CheckJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatal("stale session reached CheckJWT", w.Code)
			}
			if _, err := p.tunnelServer.validateJWTAndExtractEmail(oldSession.Value); err == nil {
				t.Fatal("stale session reached publisher authentication")
			}

			for _, tc := range []struct {
				cookie *http.Cookie
				has    bool
			}{{sessionA, true}, {sessionB, false}} {
				page := f.request("GET", "https://tunn.test/account/devices", "", "", "", tc.cookie)
				if page.Code != 200 || strings.Contains(page.Body.String(), token.Device) != tc.has {
					t.Fatal("device list changed owners", page.Code, page.Body)
				}
				keys := f.request("GET", "https://tunn.test/api/ssh/keys", "", "", tc.cookie.Value, nil)
				if keys.Code != 200 || strings.Contains(keys.Body.String(), key.Fingerprint) != tc.has {
					t.Fatal("SSH list changed owners", keys.Code, keys.Body)
				}
			}
			keyOwner, err := p.sshKeys.OwnerAccount(ctx, key.Fingerprint)
			if err != nil || keyOwner.ID != owner.ID {
				t.Fatal(keyOwner, err)
			}
			if w, err := p.sshOwnerRequest(ctx, id, "GET", "/api/ssh/keys", nil); err != nil || !strings.Contains(w.Body.String(), key.Fingerprint) {
				t.Fatal("SSH identity transferred", w, err)
			}
			denied := f.request("DELETE", "https://tunn.test/api/ssh/keys?fingerprint="+url.QueryEscape(key.Fingerprint), "", "", sessionB.Value, nil)
			if denied.Code != 404 {
				t.Fatal("B removed A's key", denied.Code, denied.Body)
			}
			// Neither old consent nor B's new proof can take A's enrolled key.
			if _, err := p.sshKeys.CompleteProof(ctx, other.ID, owner.PrimaryEmail, pendingPub, proof, signature); err == nil {
				t.Fatal("old proof transferred to B")
			}
			if err := p.sshKeys.CompleteLink(ctx, link); err == nil {
				t.Fatal("old mailbox link survived removal")
			}
			fresh, err := p.sshKeys.BeginProof(ctx, pub, owner.PrimaryEmail, other.ID)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := signer.Sign(rand.Reader, sshfront.ProofMessage(owner.PrimaryEmail, fresh))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.sshKeys.CompleteProof(ctx, other.ID, owner.PrimaryEmail, pub, fresh, sig); err == nil {
				t.Fatal("B stole A's existing key")
			}
			revoke := func(cookie *http.Cookie) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest("GET", "https://tunn.test/account/devices", nil)
				r.AddCookie(cookie)
				csrf, err := p.createCSRFToken(r, "/account/devices")
				if err != nil {
					t.Fatal(err)
				}
				return f.request("POST", "https://tunn.test/account/devices", url.Values{"device_id": {token.Device}, "csrf_token": {csrf}}.Encode(), "application/x-www-form-urlencoded", "", cookie)
			}
			if w := revoke(sessionB); w.Code != 404 {
				t.Fatal("B revoked A's device", w.Code, w.Body)
			}
			if w := revoke(sessionA); w.Code != 303 {
				t.Fatal("A lost device revocation", w.Code, w.Body)
			}
			if w, _ := durableRefresh(p, token.Refresh, strings.Repeat("e", 32)); w.Code != 401 {
				t.Fatal("revoked device refreshed", w.Code)
			}
			removedKey := f.request("DELETE", "https://tunn.test/api/ssh/keys?fingerprint="+url.QueryEscape(key.Fingerprint), "", "", sessionA.Value, nil)
			if removedKey.Code != 200 {
				t.Fatal("A lost key revocation", removedKey.Code, removedKey.Body)
			}
		})
	}
}
