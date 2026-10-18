package inspection

import (
	"os/exec"
	"testing"
)

func TestReplayFieldValidationJS(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node is required for browser field validation tests")
	}
	output, err := exec.Command("node", "../../scripts/integration-tests/replay-fields.cjs").CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
}
