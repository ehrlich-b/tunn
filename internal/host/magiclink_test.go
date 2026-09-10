package host

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/golang-jwt/jwt/v4"
)

const testMagicLinkSecret = "test-secret"

func newMagicLinkServerWithStorage(t *testing.T, secret string) (*ProxyServer, *storage.LocalStorage) {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatalf("store.InitForTest: %v", err)
	}
	s := storage.NewLocalStorage(db)
	p := &ProxyServer{
		config:  &config.Config{JWTSecret: secret},
		storage: s,
	}
	return p, s
}

func newMagicLinkServer(t *testing.T, secret string) *ProxyServer {
	t.Helper()
	p, _ := newMagicLinkServerWithStorage(t, secret)
	return p
}

func TestMagicLinkTokenRoundTrip(t *testing.T) {
	p := newMagicLinkServer(t, testMagicLinkSecret)

	token, err := p.generateMagicLinkToken("alice@example.com")
	if err != nil {
		t.Fatalf("generateMagicLinkToken: %v", err)
	}

	email, err := p.verifyMagicLinkToken(context.Background(), token)
	if err != nil {
		t.Fatalf("verifyMagicLinkToken: %v", err)
	}
	if email != "alice@example.com" {
		t.Fatalf("email = %q, want %q", email, "alice@example.com")
	}
}

func TestMagicLinkTokenReplayProtection(t *testing.T) {
	p := newMagicLinkServer(t, testMagicLinkSecret)

	token, err := p.generateMagicLinkToken("alice@example.com")
	if err != nil {
		t.Fatalf("generateMagicLinkToken: %v", err)
	}

	if _, err := p.verifyMagicLinkToken(context.Background(), token); err != nil {
		t.Fatalf("first verify: %v", err)
	}

	_, err = p.verifyMagicLinkToken(context.Background(), token)
	if err == nil {
		t.Fatal("second verify of same token: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "already used") {
		t.Fatalf("second verify error = %q, want substring %q", err.Error(), "already used")
	}
}

func TestMagicLinkTokenTamperedSignature(t *testing.T) {
	p := newMagicLinkServer(t, testMagicLinkSecret)

	token, err := p.generateMagicLinkToken("alice@example.com")
	if err != nil {
		t.Fatalf("generateMagicLinkToken: %v", err)
	}

	tampered := tamperSignature(token)
	if _, err := p.verifyMagicLinkToken(context.Background(), tampered); err == nil {
		t.Fatal("verify tampered token: expected error, got nil")
	}
}

func TestMagicLinkTokenWrongSigningKey(t *testing.T) {
	serverA, shared := newMagicLinkServerWithStorage(t, "secret-A")
	serverB := &ProxyServer{
		config:  &config.Config{JWTSecret: "secret-B"},
		storage: shared,
	}

	token, err := serverA.generateMagicLinkToken("alice@example.com")
	if err != nil {
		t.Fatalf("generateMagicLinkToken: %v", err)
	}

	if _, err := serverB.verifyMagicLinkToken(context.Background(), token); err == nil {
		t.Fatal("verify with different signing key: expected error, got nil")
	}
}

func TestMagicLinkTokenGarbageInput(t *testing.T) {
	p := newMagicLinkServer(t, testMagicLinkSecret)

	if _, err := p.verifyMagicLinkToken(context.Background(), "not a jwt at all"); err == nil {
		t.Fatal("verify garbage input: expected error, got nil")
	}
}

func TestMagicLinkTokenExpired(t *testing.T) {
	p := newMagicLinkServer(t, testMagicLinkSecret)

	now := time.Now()
	claims := jwt.MapClaims{
		"email": "alice@example.com",
		"type":  "magic_link",
		"jti":   "manually-crafted-expired-jti",
		"iat":   now.Add(-2 * time.Hour).Unix(),
		"exp":   now.Add(-1 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(testMagicLinkSecret))
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	if _, err := p.verifyMagicLinkToken(context.Background(), tokenString); err == nil {
		t.Fatal("verify expired token: expected error, got nil")
	}
}

func TestMagicLinkTokenIndependentEmails(t *testing.T) {
	p := newMagicLinkServer(t, testMagicLinkSecret)

	for _, tc := range []struct {
		email string
	}{
		{"alice@example.com"},
		{"bob@company.com"},
	} {
		token, err := p.generateMagicLinkToken(tc.email)
		if err != nil {
			t.Fatalf("generateMagicLinkToken(%q): %v", tc.email, err)
		}

		email, err := p.verifyMagicLinkToken(context.Background(), token)
		if err != nil {
			t.Fatalf("verifyMagicLinkToken(%q): %v", tc.email, err)
		}
		if email != tc.email {
			t.Fatalf("email = %q, want %q", email, tc.email)
		}
	}
}

// tamperSignature flips a character in the middle of a JWT's signature
// segment, guaranteeing the decoded signature bytes differ while keeping the
// token structurally parseable.
func tamperSignature(tokenString string) string {
	lastDot := strings.LastIndex(tokenString, ".")
	if lastDot < 0 {
		return tokenString
	}
	b := []byte(tokenString)
	// Mid-point of the signature segment - well within its significant bits
	// (unlike the trailing char, whose low bits are ignored by base64url).
	i := lastDot + 1 + (len(tokenString)-lastDot-1)/2
	if i >= len(b) {
		i = len(b) - 1
	}
	b[i] = flipChar(b[i])
	return string(b)
}

func flipChar(c byte) byte {
	switch {
	case c >= 'a' && c <= 'z':
		if c == 'z' {
			return 'a'
		}
		return c + 1
	case c >= '0' && c <= '9':
		if c == '9' {
			return '0'
		}
		return c + 1
	case c >= 'A' && c <= 'Z':
		if c == 'Z' {
			return 'A'
		}
		return c + 1
	default:
		return 'x'
	}
}
