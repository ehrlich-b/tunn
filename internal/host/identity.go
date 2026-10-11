package host

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/golang-jwt/jwt/v4"
)

// identityEmail excludes one-time login and CSRF tokens from every account
// authentication path. Older session and CLI tokens had no purpose claim.
func identityEmail(claims jwt.MapClaims) (string, error) {
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return "", fmt.Errorf("missing or expired identity token expiry")
	}
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
	if strings.HasPrefix(parts[1], "tunn_ep_") || strings.HasPrefix(parts[1], "tunn_sk_") || strings.HasPrefix(parts[1], "tunn_gr_") || strings.HasPrefix(parts[1], "tunn_mcp_") {
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
	if !p.visitorJWTConfigured() {
		return false
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return p.getJWTSigningKey(), nil
	})
	return err == nil && token.Valid
}

// Tunnel-only identities must never pass identityEmail, the account validator.
func deviceIdentity(claims jwt.MapClaims, now time.Time) (string, string, time.Time, error) {
	email, _ := claims["email"].(string)
	device, _ := claims["device"].(string)
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	if claims["type"] != "device_access" || claims["iss"] != "tunn" || claims["aud"] != "tunn-tunnels" || claims["scope"] != "publish connect" || email == "" || device == "" || exp <= float64(now.Unix()) || iat <= 0 || exp <= iat || exp-iat > deviceAccessLifetime.Seconds() || iat > float64(now.Add(time.Minute).Unix()) {
		return "", "", time.Time{}, fmt.Errorf("invalid or expired device token; run tunn login if renewal fails")
	}
	return common.NormalizeEmail(email), device, time.Unix(int64(exp), 0), nil
}

func parseDeviceToken(raw string, key []byte, now time.Time) (string, string, time.Time, error) {
	token, err := jwt.NewParser(jwt.WithoutClaimsValidation(), jwt.WithValidMethods([]string{"HS256"})).Parse(raw, func(*jwt.Token) (any, error) { return key, nil })
	if err != nil || !token.Valid {
		return "", "", time.Time{}, fmt.Errorf("invalid device signature")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", time.Time{}, fmt.Errorf("invalid device claims")
	}
	return deviceIdentity(claims, now)
}

// Used only to reject an expired device JWT after a slow registration path.
func isDeviceAccessToken(raw string) bool {
	token, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	return ok && claims["type"] == "device_access"
}
