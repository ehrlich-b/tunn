package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
				return false
			}
		}
	}
	return true
}

func validPort(port string) bool {
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func validateAddress(key, value string, listener bool) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || !validPort(port) || (host == "" && !listener) || (host != "" && !validHost(host)) {
		return fmt.Errorf("%s must be a host:port address with a port from 1 to 65535", key)
	}
	return nil
}

// validateSettings checks supplied environment values without opening files or
// contacting services. Client commands can load prod defaults without owning
// the relay's secrets or filesystem.
func (c *Config) validateSettings() error {
	for _, key := range []string{"TUNN_HOST_MODE", "TUNN_LOGIN_NODE", "TUNN_PUBLIC_MODE", "TUNN_CUSTOM_DOMAINS"} {
		if value := os.Getenv(key); value != "" && value != "true" && value != "false" {
			return fmt.Errorf("%s must be true or false", key)
		}
	}
	if !validHost(c.Domain) {
		return fmt.Errorf("TUNN_DOMAIN must be a hostname without a scheme or port")
	}
	for _, key := range []string{"TUNN_ADDR", "TUNN_HTTP2_ADDR", "TUNN_HTTP3_ADDR", "TUNN_INTERNAL_GRPC_PORT", "TUNN_SSH_ADDR", "TUNN_HTTP01_ADDR", "TUNN_MOCK_OIDC_ADDR", "TUNN_PUBLIC_ADDR", "TUNN_SERVER_ADDR"} {
		if value := os.Getenv(key); value != "" {
			if err := validateAddress(key, value, key != "TUNN_PUBLIC_ADDR" && key != "TUNN_SERVER_ADDR"); err != nil {
				return err
			}
		}
	}
	if c.NodeAddresses != "" {
		for _, addr := range strings.Split(c.NodeAddresses, ",") {
			if err := validateAddress("TUNN_NODE_ADDRESSES", strings.TrimSpace(addr), false); err != nil {
				return err
			}
		}
	}
	if !validPort(c.SMTPPort) {
		return fmt.Errorf("TUNN_SMTP_PORT must be a port from 1 to 65535")
	}
	if c.SMTPHost != "" && !validHost(c.SMTPHost) {
		return fmt.Errorf("TUNN_SMTP_HOST must be a hostname")
	}
	for _, key := range []string{"TUNN_SMTP_FROM", "TUNN_ACME_EMAIL"} {
		if value := os.Getenv(key); value != "" {
			address, err := mail.ParseAddress(value)
			if err != nil || strings.ContainsAny(value, "\r\n") || key == "TUNN_ACME_EMAIL" && address.Address != value {
				return fmt.Errorf("%s must be an email address", key)
			}
		}
	}
	for _, key := range []string{"TUNN_MOCK_OIDC_ISSUER", "TUNN_ACME_DIRECTORY", "TUNN_STRIPE_CHECKOUT_URL_MONTHLY", "TUNN_STRIPE_CHECKOUT_URL_YEARLY", "TUNN_STRIPE_PORTAL_URL"} {
		if value := os.Getenv(key); value != "" {
			u, err := url.Parse(value)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || !validHost(u.Hostname()) || u.User != nil || u.Fragment != "" || u.Port() != "" && !validPort(u.Port()) {
				return fmt.Errorf("%s must be an absolute HTTP(S) URL without credentials or a fragment", key)
			}
		}
	}
	if c.DomainKeySecret != "" {
		key, err := base64.StdEncoding.DecodeString(c.DomainKeySecret)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("TUNN_DOMAIN_KEY_SECRET must be a base64-encoded 32-byte key")
		}
	}
	for _, key := range []string{"TUNN_CERT_FILE", "TUNN_KEY_FILE", "TUNN_CA_CERT", "TUNN_SSH_HOST_KEY_FILE", "TUNN_USERS_FILE", "TUNN_DB_PATH", "TUNN_NODE_SECRET", "TUNN_JWT_SECRET", "TUNN_WELL_KNOWN_KEY", "TUNN_GITHUB_CLIENT_ID", "TUNN_GITHUB_CLIENT_SECRET", "TUNN_CLIENT_SECRET", "TUNN_SMTP_USER", "TUNN_SMTP_PASSWORD", "TUNN_STRIPE_SECRET_KEY", "TUNN_STRIPE_WEBHOOK_SECRET"} {
		if value := os.Getenv(key); value != "" && (strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n")) {
			return fmt.Errorf("%s must be nonblank and contain no control line breaks", key)
		}
	}
	return nil
}

// ValidateHost applies requirements specific to starting a relay, after CLI
// overrides. LoadConfig also serves client commands, which need no host secrets.
func (c *Config) ValidateHost() error {
	if err := c.ValidateOIDCOrgs(); err != nil {
		return err
	}
	if c.IsProd() {
		if c.PublicMode {
			return fmt.Errorf("TUNN_PUBLIC_MODE is only supported in development")
		}
		if c.JWTSecret == "" || c.JWTSecret == "dev-jwt-secret-do-not-use-in-prod" {
			return fmt.Errorf("TUNN_JWT_SECRET must be set to a production signing secret")
		}
		if !c.LoginNode && c.NodeAddresses == "" && c.FlyAppName == "" {
			return fmt.Errorf("TUNN_LOGIN_NODE must be true for a standalone relay")
		}
	}
	if (c.NodeAddresses != "" || c.FlyAppName != "") && c.NodeSecret == "" {
		return fmt.Errorf("TUNN_NODE_SECRET is required for multi-node mode")
	}
	if (c.GitHubClientID == "") != (c.GitHubClientSecret == "") {
		return fmt.Errorf("TUNN_GITHUB_CLIENT_ID and TUNN_GITHUB_CLIENT_SECRET must be configured together")
	}
	if (c.SMTPUser == "") != (c.SMTPPassword == "") {
		return fmt.Errorf("TUNN_SMTP_USER and TUNN_SMTP_PASSWORD must be configured together")
	}
	if c.SMTPHost != "" && c.SMTPFrom == "" {
		return fmt.Errorf("TUNN_SMTP_FROM is required when TUNN_SMTP_HOST is configured")
	}
	if c.SMTPHost == "" && (c.SMTPUser != "" || c.SMTPPassword != "" || c.SMTPFrom != "") {
		return fmt.Errorf("TUNN_SMTP_HOST is required for SMTP settings")
	}
	if c.SSHAddr != "" && c.SSHHostKeyFile == "" {
		return fmt.Errorf("TUNN_SSH_HOST_KEY_FILE is required when TUNN_SSH_ADDR is configured")
	}
	if c.CustomDomainsEnabled && c.LoginNode {
		if c.DomainKeySecret == "" {
			return fmt.Errorf("TUNN_DOMAIN_KEY_SECRET is required for custom domains on the login node")
		}
		if c.ACMEEmail == "" {
			return fmt.Errorf("TUNN_ACME_EMAIL is required for custom domains on the login node")
		}
	}
	if c.HostModeEnabled && (!c.LoginNode || c.PublicMode || c.NodeAddresses != "" || c.FlyAppName != "") {
		return fmt.Errorf("TUNN_HOST_MODE requires one authenticated, standalone login relay")
	}
	if !validHost(c.Domain) {
		return fmt.Errorf("TUNN_DOMAIN must be a hostname")
	}
	for _, field := range []struct{ key, value string }{{"TUNN_HTTP2_ADDR", c.HTTP2Addr}, {"TUNN_HTTP3_ADDR", c.HTTP3Addr}, {"TUNN_INTERNAL_GRPC_PORT", c.InternalGRPCPort}} {
		if err := validateAddress(field.key, field.value, true); err != nil {
			return err
		}
	}
	for _, field := range []struct{ key, path string }{{"TUNN_CERT_FILE", c.CertFile}, {"TUNN_KEY_FILE", c.KeyFile}, {"TUNN_CA_CERT", c.InternalCACert}, {"TUNN_USERS_FILE", c.UsersFile}, {"TUNN_SSH_HOST_KEY_FILE", c.SSHHostKeyFile}} {
		if field.path == "" && field.key != "TUNN_CERT_FILE" && field.key != "TUNN_KEY_FILE" {
			continue
		}
		info, err := os.Stat(field.path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s must name an existing regular file", field.key)
		}
	}
	return nil
}
