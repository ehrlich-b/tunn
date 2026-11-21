package host

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/joho/godotenv"
)

func TestBillingReadyServerAgreement(t *testing.T) {
	fixtures, err := filepath.Glob("../../scripts/testdata/billing-ready/*.vars")
	if err != nil || len(fixtures) == 0 {
		t.Fatal("missing billing fixtures", err)
	}
	for _, path := range fixtures {
		t.Run(filepath.Base(path), func(t *testing.T) {
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if strings.HasPrefix(key, "TUNN_") {
					t.Setenv(key, "")
				}
			}
			t.Setenv("TUNN_ENV", "prod")
			values, err := godotenv.Read(path)
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range values {
				t.Setenv(key, value)
			}
			cmd := exec.Command("bash", "../../scripts/check-billing-ready.sh", path)
			output, scriptErr := cmd.CombinedOutput()
			line, _, _ := strings.Cut(string(output), "\n")
			cfg, err := config.LoadConfig()
			if err != nil {
				if scriptErr == nil || line != "checkout closed" {
					t.Fatal("server rejected config but checker accepted it")
				}
				return
			}
			// Use the actual checkout availability and the same automation decision
			// used by Process, without a database or a provider/network request.
			p := &ProxyServer{config: cfg}
			data := p.revenueData()
			assertAgentKitCheckoutAvailability(t, agentKitHandler(cfg), data.MonthlyAvailable, data.YearlyAvailable)
			auto := store.NewStripeAutomation(cfg.StripeSecretKey, cfg.StripeProPriceIDs, nil)
			want := "checkout closed"
			if data.MonthlyAvailable || data.YearlyAvailable {
				want = "checkout open with manual activation"
				if auto.Configured() {
					want = "checkout open with automatic activation"
				}
			}
			if line != want {
				t.Fatalf("script mode %q disagrees with server %q", line, want)
			}
		})
	}
}
