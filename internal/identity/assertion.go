// Package identity signs short-lived, audience-bound application assertions.
package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const Lifetime = 2 * time.Minute
const Header = "X-Tunn-Identity"
const EmailHeader = "X-Tunn-User-Email"

type Key struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	D   string `json:"d,omitempty"`
}
type Ring struct {
	Active string `json:"active"`
	Keys   []Key  `json:"keys"`
}

// Load reads an operator-owned ring each time, allowing atomic key rotation.
func Load(path string) (*Ring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ring Ring
	if err := json.Unmarshal(data, &ring); err != nil {
		return nil, fmt.Errorf("invalid identity keyring")
	}
	seen := map[string]bool{}
	active := false
	for _, k := range ring.Keys {
		pub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(pub) != ed25519.PublicKeySize || k.Kid == "" || seen[k.Kid] || k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" || k.Use != "sig" {
			return nil, fmt.Errorf("invalid identity public key")
		}
		seen[k.Kid] = true
		if k.D != "" {
			seed, err := base64.RawURLEncoding.DecodeString(k.D)
			if err != nil || len(seed) != ed25519.SeedSize || !ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(pub)) {
				return nil, fmt.Errorf("invalid identity private key")
			}
		}
		if k.Kid == ring.Active && k.D != "" {
			active = true
		}
	}
	if !active {
		return nil, fmt.Errorf("active identity signing key required")
	}
	return &ring, nil
}
func (r *Ring) Sign(issuer, hostname, subject, email string, now time.Time) (string, error) {
	for _, k := range r.Keys {
		if k.Kid == r.Active {
			seed, err := base64.RawURLEncoding.DecodeString(k.D)
			if err != nil || len(seed) != 32 {
				return "", fmt.Errorf("invalid signing seed")
			}
			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": issuer, "aud": hostname, "sub": subject, "email": email, "email_verified": true, "idp": "google", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(Lifetime).Unix()})
			token.Header["kid"] = k.Kid
			return token.SignedString(ed25519.NewKeyFromSeed(seed))
		}
	}
	return "", fmt.Errorf("signing key unavailable")
}
func (r *Ring) JWKS() any {
	keys := append([]Key(nil), r.Keys...)
	for i := range keys {
		keys[i].D = ""
	}
	return struct {
		Keys []Key `json:"keys"`
	}{keys}
}
