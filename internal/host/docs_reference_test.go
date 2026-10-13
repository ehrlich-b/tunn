package host

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

func docsProxy() *ProxyServer {
	cfg := &config.Config{Domain: "tunn.to"}
	return &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: NewTunnelServer(cfg, nil, nil, nil)}
}

func TestDocsRoutes(t *testing.T) {
	p := docsProxy()
	handler := p.createHandler()
	for path := range referencePages {
		t.Run(path, func(t *testing.T) {
			for _, method := range []string{"GET", "HEAD", "POST"} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(method, "https://tunn.to"+path, nil))
				want := 200
				if method == "POST" {
					want = 405
				}
				if w.Code != want {
					t.Fatalf("%s: status %d, want %d", method, w.Code, want)
				}
				if method == "HEAD" && w.Body.Len() != 0 {
					t.Fatal("HEAD returned body")
				}
				if method == "GET" {
					body := w.Body.String()
					for _, link := range docsLinks {
						if !strings.Contains(body, `href="`+link.path+`"`) {
							t.Errorf("missing navigation to %s", link.path)
						}
					}
					if !strings.Contains(body, `id="docs-content"`) || !strings.Contains(body, "<h1") {
						t.Fatal("missing main content")
					}
					if strings.Contains(body, "{{.") {
						t.Fatal("unrendered template value")
					}
				}
			}
		})
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.to/docs/not-a-page", nil))
	if w.Code != 404 {
		t.Fatalf("unknown docs: %d", w.Code)
	}
}

// Pin the frozen plan contract and compare the rendered docs with the code's
// admission constants. A changed price/limit requires an intentional docs review.
func TestDocsPricingContract(t *testing.T) {
	p := docsProxy()
	d := p.revenueData()
	if d.MonthlyUSD != 5 || d.YearlyUSD != 48 || storage.FreeTunnelLimit != 5 || storage.ProTunnelLimit != 25 || metering.FreeMonthlyRequests != 1000000 || metering.ProMonthlyRequests != 10000000 || FreeQuotaBytes != 10000000000 || ProQuotaBytes != 500000000000 || store.MaxReservedSubdomains != 10 || store.FreeReservedSubdomains != 1 {
		t.Fatal("plan contract changed; review the docs, pricing and limits together")
	}
	if FreeQuotaBytes != metering.FreeMonthlyBytes || ProQuotaBytes != metering.ProMonthlyBytes {
		t.Fatal("host and metering byte limits differ")
	}
	check := func() {
		t.Helper()
		w := httptest.NewRecorder()
		p.handleDocs(w, httptest.NewRequest("GET", "/docs/limits", nil))
		body := w.Body.String()
		data := p.revenueData()
		rows := []string{
			fmt.Sprintf("<td>$0</td><td>$%d/mo or $%d/yr</td>", data.MonthlyUSD, data.YearlyUSD),
			fmt.Sprintf("<td>%d</td><td>%d</td>", data.FreeTunnels, data.ProTunnels),
			fmt.Sprintf("<td>%s</td><td>%s</td>", data.FreeBytes, data.ProBytes),
			fmt.Sprintf("<td>%d</td><td>%d</td>", data.FreeRequests, data.ProRequests),
			fmt.Sprintf("<td>%d</td><td>%d</td>", data.FreeReservations, data.Reservations),
		}
		for _, row := range rows {
			if !strings.Contains(body, row) {
				t.Errorf("docs do not match code: %s", row)
			}
		}
	}
	check()
	// Configured operator prices/caps must not leave stale values on the docs page.
	p.config.ProMonthlyUSD, p.config.ProYearlyUSD = 7, 72
	p.config.OwnerMonthlyBytes, p.config.OwnerMonthlyRequests = 2000000000, 100
	check()
}
