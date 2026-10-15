package host

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// identityEmail excludes one-time login and CSRF tokens from every account
// authentication path. Older session and CLI tokens had no purpose claim.
func identityEmail(claims jwt.MapClaims) (string, error) {
	if claims["provider"] == "google" && (claims["google_authoritative"] != true || claims["issuer"] != common.GoogleIssuer) {
		return "", fmt.Errorf("Google identity lacks authoritative mailbox proof")
	}
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return "", fmt.Errorf("missing or expired identity token expiry")
	}
	if purpose, exists := claims["type"]; exists && purpose != "session" && purpose != "access" {
		return "", fmt.Errorf("invalid identity token purpose")
	}
	email, ok := claims["email"].(string)
	email = common.NormalizeEmail(email)
	if !ok || email == "" {
		return "", fmt.Errorf("missing email claim")
	}
	return email, nil
}

// accountIdentityEmail applies the signed UUID and live mailbox check to every
// presentation of an account session, including bearer and publisher JWTs.
func accountIdentityEmail(ctx context.Context, authority storage.Storage, claims jwt.MapClaims) (string, error) {
	email, err := identityEmail(claims)
	if err != nil {
		return "", err
	}
	if _, bound := claims["account_id"]; !bound {
		return email, nil
	}
	if claims["type"] != "session" || !validAccountClaims(claims) || authority == nil || !authority.Available() {
		return "", fmt.Errorf("invalid account session")
	}
	id, _ := claims["account_id"].(string)
	account, err := authority.GetAccount(ctx, id)
	if err != nil || account == nil {
		return "", fmt.Errorf("account session unavailable")
	}
	for _, alias := range account.Emails {
		if common.NormalizeEmail(alias.Email) == email {
			return email, nil
		}
	}
	return "", fmt.Errorf("session mailbox no longer belongs to account")
}

func deviceAccount(ctx context.Context, authority storage.Storage, claims jwt.MapClaims) (*storage.Account, error) {
	id, _ := claims["account_id"].(string)
	if id == "" || authority == nil || !authority.Available() {
		return nil, fmt.Errorf("device account unavailable")
	}
	account, err := authority.GetAccount(ctx, id)
	if err != nil || account == nil || account.OperationalState != "active" {
		return nil, fmt.Errorf("device account unavailable or suspended")
	}
	return account, nil
}

// The bearer header has already passed the identity validator. Use its signed
// UUID for authorization so a concurrent mailbox removal cannot change owners.
func (p *ProxyServer) bearerAccount(r *http.Request, email, header string) (*storage.Account, error) {
	parts := strings.Fields(r.Header.Get(header))
	if len(parts) == 2 {
		if id := signedAccountID(parts[1]); id != "" {
			return p.storage.GetAccount(r.Context(), id)
		}
	}
	return p.storage.GetAccountByEmail(r.Context(), common.NormalizeEmail(email))
}

// Read only after the caller has verified the token signature and purpose.
func signedAccountID(raw string) string {
	token, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return ""
	}
	id, _ := token.Claims.(jwt.MapClaims)["account_id"].(string)
	return id
}

// isPlatformAuthorization recognizes relay credentials even when they have
// expired or belong to another endpoint. Signature validation is retained;
// skipping expiry here is only for removing credentials from forwarded traffic.
func (p *ProxyServer) isPlatformAuthorization(value string) bool {
	if _, ok := appBearer(value); ok {
		return true
	}
	if _, ok := appBasic(value); ok {
		return true
	}
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}
	if strings.HasPrefix(parts[1], "tunn_app_") || strings.HasPrefix(parts[1], "tunn_ep_") || strings.HasPrefix(parts[1], "tunn_sk_") || strings.HasPrefix(parts[1], "tunn_gr_") || strings.HasPrefix(parts[1], "tunn_mcp_") {
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
	accountID, _ := claims["account_id"].(string)
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	if claims["type"] != "device_access" || claims["iss"] != "tunn" || claims["aud"] != "tunn-tunnels" || claims["scope"] != "publish connect" || email == "" || device == "" || accountID == "" || exp <= float64(now.Unix()) || iat <= 0 || exp <= iat || exp-iat > deviceAccessLifetime.Seconds() || iat > float64(now.Add(time.Minute).Unix()) {
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

// Compare UUID values independently of their textual case and format.
func sameAccountID(a, b string) bool {
	first, err := uuid.Parse(a)
	if err != nil {
		return false
	}
	second, err := uuid.Parse(b)
	return err == nil && first == second
}

// Resolve obsolete UUIDs through the authoritative merge aliases before comparison.
func sameResolvedAccount(ctx context.Context, authority storage.Storage, a, b string) bool {
	if sameAccountID(a, b) {
		return true
	}
	firstID, firstErr := uuid.Parse(a)
	secondID, secondErr := uuid.Parse(b)
	if firstErr != nil || secondErr != nil || authority == nil || !authority.Available() {
		return false
	}
	first, err := authority.GetAccount(ctx, firstID.String())
	if err != nil || first == nil {
		return false
	}
	second, err := authority.GetAccount(ctx, secondID.String())
	return err == nil && second != nil && sameAccountID(first.ID, second.ID)
}
