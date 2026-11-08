package host

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/storage"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestPlanNameNoticeScope(t *testing.T) {
	for _, plan := range []string{"free", "pro"} {
		t.Run(plan, func(t *testing.T) {
			local := securityDB(t)
			ctx := context.Background()
			account, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.com"}, "github")
			if err != nil {
				t.Fatal(err)
			}
			if plan == "pro" {
				if err := local.UpdatePlan(ctx, account.ID, plan); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"first", "second", "first"} {
				reg, err := local.RegisterTunnel(ctx, name, account.ID, "fixture")
				if err != nil || !reg.Allowed {
					t.Fatalf("%s: %v %v", name, reg, err)
				}
				wantNotice := plan == "free" && name == "second"
				if (reg.NoticeCode == "name_not_kept") != wantNotice || (reg.Notice != "") != wantNotice {
					t.Fatalf("%s: unexpected notice: %+v", name, reg)
				}
				if err := local.UnregisterTunnel(ctx, name); err != nil {
					t.Fatal(err)
				}
			}
			names, err := local.AccountStore().GetReservedSubdomains(account.ID)
			want := 1
			if plan == "pro" {
				want = 2
			}
			if err != nil || len(names) != want {
				t.Fatalf("reservations: %v %v", names, err)
			}
		})
	}
}

func TestPlanLimitLocalRefusal(t *testing.T) {
	cfg := testConfig()
	cfg.PublicMode = true
	relay := NewTunnelServer(cfg, nil, nil, nil)
	for i := 0; i < storage.FreeTunnelLimit; i++ {
		relay.tunnels[fmt.Sprint(i)] = &TunnelConnection{CreatorEmail: "public@tunn.local"}
	}
	stream := &mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}
	stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "sixth"}}}
	close(stream.recvQueue)
	if err := relay.EstablishTunnel(stream); err == nil {
		t.Fatal("sixth tunnel admitted")
	}
	response := stream.sentMsgs[0].GetRegisterResponse()
	if response.Success || response.ErrorCode != "tunnel_limit" {
		t.Fatalf("refusal: %v", response)
	}
	for _, want := range []string{"Free", "5/5", "$5 a month or $48 a year", "https://tunn.to/pricing"} {
		if !strings.Contains(response.ErrorMessage, want) {
			t.Errorf("refusal missing %q", want)
		}
	}
	if text := tunnelLimitMessage("pro", 25, 25); !strings.Contains(text, "Pro tunnel limit reached: 25/25") || strings.Contains(text, "upgrade") {
		t.Fatalf("Pro refusal: %s", text)
	}
}
