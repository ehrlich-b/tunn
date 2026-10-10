package host

import (
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// identityEmail excludes one-time login and CSRF tokens from every account
// authentication path. Older session and CLI tokens had no purpose claim.
func identityEmail(claims jwt.MapClaims) (string, error) {
	if purpose, exists := claims["type"]; exists && purpose != "session" && purpose != "access" {
		return "", fmt.Errorf("invalid identity token purpose")
	}
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return "", fmt.Errorf("missing email claim")
	}
	return email, nil
}

// isPlatformAuthorization recognizes relay credentials even when they have
// expired or belong to another endpoint. Signature validation is retained;
// skipping expiry here is only for removing credentials from forwarded traffic.
func (p *ProxyServer) isPlatformAuthorization(value string) bool {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}
	if strings.HasPrefix(parts[1], "tunn_ep_") || strings.HasPrefix(parts[1], "tunn_sk_") {
		return true
	}
	if p.config != nil && p.config.ClientSecret != "" && subtle.ConstantTimeCompare([]byte(parts[1]), []byte(p.config.ClientSecret)) == 1 {
		return true
	}
	if p.tunnelServer != nil && p.tunnelServer.validateUserToken(parts[1]) != "" {
		return true
	}
	if strings.Count(parts[1], ".") != 2 {
		return false
	}
	if p.config == nil {
		return false
	}
	parser := jwt.Parser{SkipClaimsValidation: true}
	token, err := parser.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return p.getJWTSigningKey(), nil
	})
	return err == nil && token.Valid
}
