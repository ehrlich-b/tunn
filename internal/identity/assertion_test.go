package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestAssertionRotationAudienceExpiryAndPublicJWKS(t *testing.T) {
	makeKey := func(kid string) Key {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return Key{Kid: kid, Kty: "OKP", Crv: "Ed25519", Alg: "EdDSA", Use: "sig", X: base64.RawURLEncoding.EncodeToString(pub), D: base64.RawURLEncoding.EncodeToString(key.Seed())}
	}
	old, next := makeKey("old"), makeKey("next")
	path := filepath.Join(t.TempDir(), "keys.json")
	write := func(ring Ring) {
		data, _ := json.Marshal(ring)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(Ring{Active: "old", Keys: []Key{old}})
	ring, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ring.Sign("https://tunn.test", "api.apps.ehrlich.dev", "subject", "ehrlich.bryan@gmail.com", "github", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	old.D = ""
	write(Ring{Active: "next", Keys: []Key{old, next}})
	ring, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := ring.Sign("https://tunn.test", "api.apps.ehrlich.dev", "subject", "ehrlich.bryan@gmail.com", "github", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verify := func(raw string) (*jwt.Token, error) {
		return jwt.Parse(raw, func(tok *jwt.Token) (interface{}, error) {
			for _, k := range ring.Keys {
				if tok.Header["kid"] == k.Kid {
					pub, _ := base64.RawURLEncoding.DecodeString(k.X)
					return ed25519.PublicKey(pub), nil
				}
			}
			return nil, os.ErrNotExist
		}, jwt.WithValidMethods([]string{"EdDSA"}))
	}
	for _, raw := range []string{token, fresh} {
		parsed, err := verify(raw)
		if err != nil || !parsed.Valid {
			t.Fatal("rotation lost active assertions", err)
		}
		claims := parsed.Claims.(jwt.MapClaims)
		if !claims.VerifyAudience("api.apps.ehrlich.dev", true) || claims.VerifyAudience("other.apps.ehrlich.dev", true) {
			t.Fatal("audience binding failed")
		}
	}
	expired, _ := ring.Sign("https://tunn.test", "api.apps.ehrlich.dev", "subject", "email", "magic_link", time.Now().Add(-3*time.Minute))
	if _, err := verify(expired); err == nil {
		t.Fatal("expired assertion accepted")
	}
	data, _ := json.Marshal(ring.JWKS())
	if strings.Contains(string(data), `"d":`) {
		t.Fatal("JWKS contains private seeds")
	}
	write(Ring{Active: "next", Keys: []Key{next}})
	ring, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(token); err == nil {
		t.Fatal("removed key still trusted")
	}
	next.X = old.X
	write(Ring{Active: "next", Keys: []Key{next}})
	if _, err := Load(path); err == nil {
		t.Fatal("mismatched key accepted")
	}
}
