package cliopts

import (
	"testing"
	"time"
)

func TestWebhookCLIOptions(t *testing.T) {
	for _, args := range [][]string{{"8080", "--public", "--verify-webhook", "stripe", "--webhook-secret-file", "fixture.key"}, {"--verify-webhook=slack", "--webhook-secret-file=fixture.key", "--webhook-tolerance=60s", "8080"}} {
		o, err := ParseServe(args, true)
		if err != nil || o.WebhookSecretFile != "fixture.key" || o.WebhookTolerance < time.Second {
			t.Fatalf("valid flags: %v", err)
		}
	}
	for _, args := range [][]string{
		{"8080", "--verify-webhook=stripe"}, {"8080", "--webhook-secret-file=fixture.key"},
		{"8080", "--verify-webhook=bad", "--webhook-secret-file=fixture.key"},
		{"8080", "--verify-webhook=slack", "--webhook-secret-file=fixture.key", "--webhook-tolerance=0s"},
		{"8080", "--verify-webhook=slack", "--webhook-secret-file=fixture.key", "--webhook-tolerance=1.5s"},
		{"8080", "--verify-webhook=github", "--webhook-secret-file=fixture.key", "--webhook-tolerance=60s"},
		{"8080", "--webhook-tolerance=1h"},
		{"8080", "--webhook-tolerance=5m"},
		{"8080", "--verify-webhook="},
	} {
		if _, err := ParseServe(args, true); err == nil {
			t.Fatal("invalid flags accepted")
		}
	}
	if _, err := ParseSSHPublication([]string{"--verify-webhook=github", "--webhook-secret-file=fixture.key"}, "serve"); err == nil {
		t.Fatal("SSH silently ignored webhook policy")
	}
	if _, err := ParseSSHPublication([]string{"--webhook-tolerance=5m"}, "serve"); err == nil {
		t.Fatal("SSH silently ignored explicit default webhook flag")
	}
}
