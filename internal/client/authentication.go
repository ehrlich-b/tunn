package client

import (
	"errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
)

// AuthenticationFailure distinguishes expired login from admission limits.
func AuthenticationFailure(err error) bool {
	if err == nil {
		return false
	}
	if status.Code(err) == codes.Unauthenticated || terminalCredentialError(err) {
		return true
	}
	var permanent *permanentTunnelError
	if !errors.As(err, &permanent) || permanent.kind != FailureRegistration {
		return false
	}
	message := strings.ToLower(permanent.err.Error())
	return strings.Contains(message, "authentication required") || strings.Contains(message, "invalid or expired token")
}

// RetryableCredentialError keeps temporary renewal failures distinct from a
// revoked login. It never exposes the private transport response.
func RetryableCredentialError(err error) bool {
	var refresh *credentialRefreshError
	return errors.As(err, &refresh) && !refresh.terminal
}
