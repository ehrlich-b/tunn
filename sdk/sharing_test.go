package tunn

import (
	"context"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"testing"
	"time"
)

func TestSDKWebExposureDefaultAndExplicitPublic(t *testing.T) {
	for _, public := range []bool{false, true} {
		o := fixtureOptions()
		o.Public = public
		dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
			reg, err := registration(stream)
			if err != nil {
				return err
			}
			mode := "private"
			if public {
				mode = "public"
			}
			if reg.ExposureVersion != 1 || reg.ExposureMode != mode {
				t.Errorf("SDK exposure=%v", reg)
			}
			if err = acceptRegistration(stream, reg); err != nil {
				return err
			}
			return drainUntilCanceled(stream)
		})
		o.TLSConfig = tlsConfig
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		tunnel := startFixtureTunnel(t, ctx, o, dial, nil)
		if _, err := tunnel.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
		tunnel.Close()
	}
	o := fixtureOptions()
	o.Public = true
	o.AllowedEmails = []string{"alice@example.com"}
	if _, err := Publish(context.Background(), o); err == nil {
		t.Fatal("public and person-only options accepted")
	}
}
func TestSDKRefusesRelayWithoutPrivateSharing(t *testing.T) {
	dial, tlsConfig := startFixture(t, func(stream pb.TunnelService_EstablishTunnelServer) error {
		reg, err := registration(stream)
		if err != nil {
			return err
		}
		if err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://" + reg.TunnelId + ".sdk.test"}}}); err != nil {
			return err
		}
		return drainUntilCanceled(stream)
	})
	o := fixtureOptions()
	o.TLSConfig = tlsConfig
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tunnel := startFixtureTunnel(t, ctx, o, dial, nil)
	if _, err := tunnel.WaitReady(ctx); err == nil {
		t.Fatal("old relay silently exposed private SDK resource")
	}
}
