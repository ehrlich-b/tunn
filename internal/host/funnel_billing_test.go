package host

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFunnelRejectedWebhookMetadataAlerts(t *testing.T) {
	p, _ := stripeCorrectnessFixture(t)
	p.config.StripeWebhookSecret = "whsec_metadata_fixture"
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	body := `{"id":"evt_metadata","type":"checkout.session.completed","data":{"object":{"id":"cs_metadata","mode":"subscription","customer":{"id":"cus_private_sentinel","email":"private@example.invalid"},"subscription":"sub_metadata"}}}`
	w := stripeFixtureRequest(p, body, signedStripeFixture(body, p.config.StripeWebhookSecret, time.Now().Unix()))
	if w.Code != 400 || !strings.Contains(logs.String(), `level=ERROR msg="billing webhook metadata rejected"`) {
		t.Fatalf("status=%d logs=%s", w.Code, logs.String())
	}
	if strings.Contains(logs.String(), "private") || strings.Contains(logs.String(), p.config.StripeWebhookSecret) {
		t.Fatalf("sensitive metadata logged: %s", logs.String())
	}
	report := filepath.Join(t.TempDir(), "funnel.json")
	if err := os.WriteFile(report, []byte(`{"days":[],"checkout_without_pro":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"--funnel", report}} {
		cmd := exec.Command("python3", append([]string{"-B", "../../scripts/launch-watch.py"}, args...)...)
		cmd.Stdin = strings.NewReader(logs.String())
		out, err := cmd.CombinedOutput()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 || !strings.Contains(string(out), "invalid metadata: 1") {
			t.Fatalf("args=%v err=%v output=%s", args, err, out)
		}
	}
}
