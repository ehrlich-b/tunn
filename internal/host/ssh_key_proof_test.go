package host

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/sshfront"
	"golang.org/x/crypto/ssh"
)

func TestSSHKeyHTTPPossessionAndIdentityProof(t *testing.T) {
	p, _, _ := sshRelay(t, true)
	victim := sshSigner(t)
	pub := string(ssh.MarshalAuthorizedKey(victim.PublicKey()))
	parsed, err := sshfront.ParseKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"alice@example.com", "mallory@example.com"} {
		if _, err := p.storage.FindOrCreateByEmails(context.Background(), []string{email}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	request := func(email string, payload any) *httptest.ResponseRecorder {
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		token, err := p.generateJWT(email)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "https://tunn.test/api/ssh/keys", strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		p.handleSSHKeys(w, r)
		return w
	}
	w := request("alice@example.com", map[string]string{"public_key": pub})
	if w.Code != http.StatusAccepted {
		t.Fatal(w.Code, w.Body)
	}
	var challenge struct{ Challenge, Email, Message string }
	if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	if owner, err := p.sshKeys.Owner(context.Background(), parsed.Fingerprint); err != nil || owner != "" {
		t.Fatal("challenge squatted key", owner, err)
	}
	if challenge.Email != "alice@example.com" || challenge.Message != string(sshfront.ProofMessage(challenge.Email, challenge.Challenge)) {
		t.Fatal(challenge)
	}
	good, err := victim.Sign(rand.Reader, []byte(challenge.Message))
	if err != nil {
		t.Fatal(err)
	}
	bad, err := sshSigner(t).Sign(rand.Reader, []byte(challenge.Message))
	if err != nil {
		t.Fatal(err)
	}
	payload := func(public string, signature *ssh.Signature) any {
		return struct {
			PublicKey string         `json:"public_key"`
			Challenge string         `json:"challenge"`
			Signature *ssh.Signature `json:"signature"`
		}{public, challenge.Challenge, signature}
	}
	for _, tc := range []struct {
		name, email, public string
		signature           *ssh.Signature
	}{
		{"wrong signer", "alice@example.com", pub, bad},
		{"different authenticated identity", "mallory@example.com", pub, good},
		{"different submitted key", "alice@example.com", string(ssh.MarshalAuthorizedKey(sshSigner(t).PublicKey())), good},
		{"missing signature", "alice@example.com", pub, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(tc.email, payload(tc.public, tc.signature))
			if w.Code == 200 {
				t.Fatal("invalid proof enrolled key")
			}
		})
	}
	w = request("alice@example.com", payload(pub, good))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w = request("alice@example.com", payload(pub, good))
	if w.Code == 200 {
		t.Fatal("one-time proof replayed")
	}
	if owner, err := p.sshKeys.Owner(context.Background(), parsed.Fingerprint); err != nil || owner != "alice@example.com" {
		t.Fatal(owner, err)
	}
	// Both signed proof and email link authority issued before removal are stale.
	w = request("alice@example.com", map[string]string{"public_key": pub})
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	stale, err := victim.Sign(rand.Reader, []byte(challenge.Message))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.sshKeys.Remove(context.Background(), []string{"alice@example.com"}, parsed.Fingerprint); err != nil {
		t.Fatal(err)
	}
	w = request("alice@example.com", payload(pub, stale))
	if w.Code == 200 {
		t.Fatal("pre-removal signature restored revoked key")
	}
	// The removed key's actual holder can enroll with new consent and fresh proof.
	w = request("alice@example.com", map[string]string{"public_key": pub})
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	fresh, err := victim.Sign(rand.Reader, []byte(challenge.Message))
	if err != nil {
		t.Fatal(err)
	}
	w = request("alice@example.com", payload(pub, fresh))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
}

func TestSSHKeyAccountBudgetUsesCanonicalIdentity(t *testing.T) {
	p, _, _ := sshRelay(t, true)
	if _, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"owner@example.com", "alias@example.com"}, "test"); err != nil {
		t.Fatal(err)
	}
	primary, err := p.sshAccountBudget(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	alias, err := p.sshAccountBudget(context.Background(), "alias@example.com")
	if err != nil || alias != primary {
		t.Fatal("alias escaped account budget", alias, primary, err)
	}
}
