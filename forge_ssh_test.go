package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/golang-jwt/jwt/v4"
)

func forgeLoginFixture(t *testing.T) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": "bryan@example.test", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("offline-fixture-signing-key"))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestForgeSSHAccountOnlyPublication(t *testing.T) {
	t.Setenv("TUNN_SECRET", "")
	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	// An old endpoint capability must not be registered or overwritten.
	path, err := client.SaveEndpointToken("forge-ssh", "tunn_ep_old-capability")
	if err != nil {
		t.Fatal(err)
	}
	opts, err := parseTCPFlags([]string{"--account-only", "--name", "forge-ssh", "127.0.0.1:22"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := prepareRawAccess(opts, forgeLoginFixture(t), "forge-ssh")
	if err != nil || a.creator != "bryan@example.test" || !reflect.DeepEqual(a.emails, []string{a.creator}) || len(a.digest) != 0 || a.path != "" {
		t.Fatalf("account-only publication = %+v, %v", a, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "tunn_ep_old-capability\n" {
		t.Fatalf("old capability was changed: %q, %v", data, err)
	}
	if _, err := prepareRawAccess(opts, "publisher-secret", "forge-ssh"); err == nil {
		t.Fatal("accepted secret authentication for an account-only publisher")
	}
	for _, flag := range []string{"--public", "--secret=publisher-secret"} {
		if _, err := parseTCPFlags([]string{"--account-only", flag, "22"}); err == nil {
			t.Errorf("accepted %s with --account-only", flag)
		}
	}
	t.Setenv("TUNN_SECRET", "inherited-secret")
	if _, err := parseTCPFlags([]string{"--account-only", "22"}); err == nil {
		t.Fatal("accepted inherited publisher secret")
	}
}

func TestForgeSSHPrivateAccountGrant(t *testing.T) {
	t.Setenv("TUNN_SECRET", "")
	opts, err := parseTCPFlags([]string{"--account-only", "--allow", "guest@example.test", "22"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := prepareRawAccess(opts, forgeLoginFixture(t), "ssh")
	if err != nil || !reflect.DeepEqual(a.emails, []string{"guest@example.test", "bryan@example.test"}) || len(a.digest) != 0 {
		t.Fatalf("explicit account grant = %+v, %v", a, err)
	}
}

func TestForgeSSHProxyCommandFlags(t *testing.T) {
	opts, err := parseConnectFlags([]string{"--stdio", "--account", "forge-ssh"})
	if err != nil || !opts.stdio || !opts.account {
		t.Fatalf("ProxyCommand flags = %+v, %v", opts, err)
	}
	for _, args := range [][]string{
		{"--stdio", "--listen=127.0.0.1:0", "forge-ssh"},
		{"--account", "--token=capability", "forge-ssh"},
		{"--account", "--token-file=capability", "forge-ssh"},
		{"--account", "--public", "forge-ssh"},
		{"--account", "https://forge-ssh.attacker.test"},
		{"--stdio"},
	} {
		if _, err := parseConnectFlags(args); err == nil {
			t.Errorf("accepted unsafe or ambiguous flags %v", args)
		}
	}
}

func TestForgeSSHAccountCredentialDoesNotFallback(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	t.Setenv("TUNN_ENDPOINT_TOKEN", "tunn_ep_inherited-capability")
	if _, err := client.SaveEndpointToken("forge-ssh", "tunn_ep_local-capability"); err != nil {
		t.Fatal(err)
	}
	opts := &connectCommandOptions{account: true}
	if _, err := loadConnectToken(opts, "forge-ssh"); err == nil {
		t.Fatal("missing login fell back to an endpoint capability")
	}
	login := forgeLoginFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(login+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := loadConnectToken(opts, "forge-ssh"); err != nil || token != login {
		t.Fatalf("account credential = %q, %v", token, err)
	}
	if _, err := loadConnectToken(opts, ""); err == nil {
		t.Fatal("account login was offered to an explicit remote URL")
	}
	if err := os.WriteFile(filepath.Join(dir, "empty"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConnectToken(&connectCommandOptions{tokenFile: filepath.Join(dir, "empty")}, "forge-ssh"); err == nil {
		t.Fatal("empty explicit token file fell back to another credential")
	}
}
