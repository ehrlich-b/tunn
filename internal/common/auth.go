package common

import (
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

// AuthTransport adds an Authorization header to requests
type AuthTransport struct {
	Transport http.RoundTripper
	Token     string
}

// RoundTrip implements the http.RoundTripper interface
func (t *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.Token)
	LogDebug("sending request", "url", req.URL, "token", t.Token)
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		LogError("request failed", "url", req.URL, "error", err)
	} else {
		LogDebug("response received", "url", req.URL, "status", resp.Status)
		if resp.StatusCode == http.StatusUnauthorized {
			LogError("authentication failure", "token", t.Token)
		}
	}
	return resp, err
}

// AuthMiddleware creates an authentication middleware
func AuthMiddleware(token string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			receivedAuth := r.Header.Get("Authorization")
			expectedAuth := "Bearer " + token

			LogDebug("auth: checking token", "remote_addr", r.RemoteAddr)
			LogDebug("auth: received token", "token", receivedAuth)
			LogDebug("auth: expected token", "token", expectedAuth)

			if receivedAuth != expectedAuth {
				LogError("auth: invalid token", "remote_addr", r.RemoteAddr, "received", receivedAuth, "expected", expectedAuth)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			LogDebug("auth: valid token", "remote_addr", r.RemoteAddr)
			next(w, r)
		}
	}
}

// ExtractEmailFromJWT extracts the email claim from a JWT token string
// Returns the email and an error if parsing fails
// Note: This does NOT validate the signature - it only parses the claims
// Use this when you've already validated the JWT elsewhere (e.g., via JWKS)
func ExtractEmailFromJWT(tokenString string) (string, error) {
	// Parse without validation (signature already validated by proxy)
	parser := jwt.Parser{SkipClaimsValidation: true}
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid JWT claims format")
	}

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return "", fmt.Errorf("email claim not found or empty in JWT")
	}

	return email, nil
}
