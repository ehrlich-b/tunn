package common

import (
	"log/slog"
	"net/http"
)

// AuthTransport adds an Authorization header to requests
type AuthTransport struct {
	Transport http.RoundTripper
	Token     string
}

// RoundTrip implements the http.RoundTripper interface
func (t *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.Token)
	slog.Debug("sending request", "url", req.URL, "token", t.Token)
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		slog.Error("request failed", "url", req.URL, "error", err)
	} else {
		slog.Debug("response received", "url", req.URL, "status", resp.Status)
		if resp.StatusCode == http.StatusUnauthorized {
			slog.Error("authentication failure", "token", t.Token)
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

			slog.Debug("auth: checking token", "remote_addr", r.RemoteAddr)
			slog.Debug("auth: received token", "token", receivedAuth)
			slog.Debug("auth: expected token", "token", expectedAuth)

			if receivedAuth != expectedAuth {
				slog.Warn("auth: invalid token", "remote_addr", r.RemoteAddr, "received", receivedAuth, "expected", expectedAuth)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			slog.Info("auth: valid token", "remote_addr", r.RemoteAddr)
			next(w, r)
		}
	}
}
