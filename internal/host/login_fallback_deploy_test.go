package host

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Keep the immediate sign-in recovery separate from the blocked carrier rollout.
func TestLoginFallbackDeploymentSafety(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "DEPLOY.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(content)
	prose := strings.Join(strings.Fields(doc), " ")
	t.Run("immediate_recovery", func(t *testing.T) {
		for _, required := range []string{
			"Step 1 alone restores email sign-in",
			"current production image (`110485c`)",
			"fly secrets unset TUNN_GITHUB_CLIENT_ID TUNN_GITHUB_CLIENT_SECRET -a tunn",
		} {
			if !strings.Contains(prose, required) {
				t.Errorf("missing immediate recovery guidance: %s", required)
			}
		}
	})
	t.Run("carrier_release_gate", func(t *testing.T) {
		for _, required := range []string{
			"[RELEASE-VALIDATION.md](RELEASE-VALIDATION.md)",
			"four blockers",
			"[DEPLOY-RUNBOOK.md](DEPLOY-RUNBOOK.md)",
			"fly.release.toml", "immutable image digest",
			"--only-machines", "--update-only --ha=false",
			"exists only in this lane", "schema migrations",
		} {
			if !strings.Contains(prose, required) {
				t.Errorf("missing carrier release constraint: %s", required)
			}
		}
		// Executable recovery instructions must not deploy the carrier or switch
		// to a branch that is unavailable in the production checkout.
		for _, block := range regexp.MustCompile("(?s)```sh\n(.*?)```").FindAllStringSubmatch(doc, -1) {
			for _, line := range strings.Split(strings.TrimSpace(block[1]), "\n") {
				switch strings.TrimSpace(line) {
				case "fly secrets unset TUNN_GITHUB_CLIENT_ID TUNN_GITHUB_CLIENT_SECRET -a tunn",
					"fly secrets set TUNN_GOOGLE_CLIENT_ID=... TUNN_GOOGLE_CLIENT_SECRET=... -a tunn":
				default:
					t.Errorf("unexpected executable recovery command; carrier rollout belongs in the gated runbook: %s", line)
				}
			}
		}
	})
	t.Run("restart_disclosure", func(t *testing.T) {
		for _, required := range []string{"restarts every machine immediately", "drops publisher streams"} {
			if !strings.Contains(prose, required) {
				t.Errorf("missing secret-change impact: %s", required)
			}
		}
	})
}
