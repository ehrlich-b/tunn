package main

import (
	"testing"
	"time"
)

func TestWebhookServeCommandOptions(t *testing.T) {
	o, err := parseServeFlags([]string{"8080", "--verify-webhook=slack", "--webhook-secret-file=fixture.key", "--webhook-tolerance=60s"})
	if err != nil || o.webhookProvider != "slack" || o.webhookSecretFile != "fixture.key" || o.webhookTolerance != time.Minute {
		t.Fatalf("CLI did not carry webhook options: %v", err)
	}
}
