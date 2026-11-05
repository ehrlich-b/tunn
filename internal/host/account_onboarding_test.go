package host

import (
	"context"
	"fmt"
	"html"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/metering"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

type onboardingMeter struct {
	metering.Backend
	usage *meterpb.ExportResponse
}

func TestAccountTunnelPreview(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	for i := 1; i < 8; i++ {
		name := fmt.Sprintf("customer-billing-webhook-staging-service-%d", i)
		f.p.tunnelServer.tunnels[name] = &TunnelConnection{TunnelID: name, TargetURL: "http", AccountID: f.tunnel.AccountID}
	}
	page := f.call("GET", "/account", nil, f.cookie, nil)
	body := page.Body.String()
	if page.Code != 200 || strings.Contains(body, "Start a private tunnel") {
		t.Fatalf("active account: %d", page.Code)
	}
	if got := strings.Count(body, ` hidden><details>`); got != 4 {
		t.Fatalf("hidden preview rows = %d, want 4", got)
	}
	if !strings.Contains(body, `>+4 more</button>`) || !strings.Contains(body, `aria-controls="live-tunnel-list"`) {
		t.Fatal("missing inline expansion control")
	}
}

func (m onboardingMeter) Export(context.Context, *meterpb.ExportRequest) (*meterpb.ExportResponse, error) {
	return m.usage, nil
}

func TestAccountOnboarding(t *testing.T) {
	for _, tc := range []struct {
		name        string
		online      bool
		bytes       int64
		requests    int64
		breakdown   bool
		unavailable bool
		partial     bool
		want        bool
	}{
		{name: "new account", want: true},
		{name: "online without traffic", online: true},
		{name: "transfer without breakdown", bytes: 1024, want: true},
		{name: "requests without breakdown", requests: 1, want: true},
		{name: "traffic after disconnect", bytes: 1024, requests: 1, breakdown: true, want: true},
		{name: "usage unavailable", unavailable: true, want: true},
		{name: "relay unavailable", partial: true},
		{name: "usage and relay unavailable", unavailable: true, partial: true},
		{name: "exhausted account", bytes: GetQuotaBytes("free")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWebInspectorFixture(t, 0, 0)
			if !tc.online {
				delete(f.p.tunnelServer.tunnels, f.tunnel.TunnelID)
			}
			usage := &meterpb.ExportResponse{OwnerUsage: &meterpb.Usage{TotalBytes: tc.bytes, AdmittedRequests: tc.requests}}
			if tc.breakdown {
				usage.Usage = []*meterpb.Usage{{Endpoint: "previous-tunnel", AdmittedRequests: tc.requests, ResponseBytes: tc.bytes}}
			}
			f.p.meter = onboardingMeter{Backend: f.p.meter, usage: usage}
			if tc.unavailable {
				f.p.meter = nil
			}
			if tc.partial {
				f.p.nodeClients = map[string]internalpb.InternalServiceClient{"offline": unavailableAccountTunnelPeer{}}
			}
			page := f.call("GET", "/account", nil, f.cookie, nil)
			if page.Code != 200 {
				t.Fatalf("account: %d %s", page.Code, page.Body)
			}
			body := page.Body.String()
			if got := strings.Contains(body, "Start a private tunnel"); got != tc.want {
				t.Fatalf("onboarding visible = %v, want %v", got, tc.want)
			}
			for _, command := range []string{defaultFirstTunnelCommands.Install, defaultFirstTunnelCommands.Run} {
				value := html.EscapeString(command)
				for _, fragment := range []string{`data-copy="` + value + `"`, `>` + value + `</code>`} {
					if got := strings.Contains(body, fragment); got != tc.want {
						t.Errorf("command %q present = %v, want %v", fragment, got, tc.want)
					}
				}
			}
			for _, meter := range []string{"This month", ">Transfer<", ">Requests: unlimited (fair use)<", "Tunnels at once", "usage-bar"} {
				if !strings.Contains(body, meter) {
					t.Errorf("missing usage content %q", meter)
				}
			}
		})
	}
}
