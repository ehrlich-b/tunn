package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ipb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type permissionAdmissionPeer struct {
	ipb.InternalServiceClient
	addr, mode string
}

func (c permissionAdmissionPeer) FindTunnel(context.Context, *ipb.FindTunnelRequest, ...grpc.CallOption) (*ipb.FindTunnelResponse, error) {
	return &ipb.FindTunnelResponse{Found: true, NodeAddress: c.addr}, nil
}
func (c permissionAdmissionPeer) CheckForwardedPermission(ctx context.Context, _ *ipb.ForwardedPermissionRequest, _ ...grpc.CallOption) (*ipb.ForwardedPermissionResponse, error) {
	switch c.mode {
	case "unimplemented":
		return nil, status.Error(codes.Unimplemented, "fixture")
	case "stalled":
		<-ctx.Done()
		return nil, ctx.Err()
	case "old-contract":
		return &ipb.ForwardedPermissionResponse{Allowed: true}, nil
	default:
		return &ipb.ForwardedPermissionResponse{Version: forwardPermissionVersion, Status: http.StatusForbidden}, nil
	}
}
func TestForwardedAdmissionRequiresPermissionCapability(t *testing.T) {
	for _, mode := range []string{"absent", "unimplemented", "denied", "stalled", "old-contract"} {
		t.Run(mode, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); _, _ = w.Write([]byte("fast response")) }))
			defer upstream.Close()
			p := securityProxy(securityDB(t))
			p.config.Insecure = true
			p.config.NodeSecret = "fixture-cluster"
			addr := strings.TrimPrefix(upstream.URL, "https://")
			if mode != "absent" {
				p.nodeClients = map[string]ipb.InternalServiceClient{"publisher": permissionAdmissionPeer{addr: addr, mode: mode}}
			}
			r := httptest.NewRequest("GET", "https://api.tunn.test/", nil)
			w := httptest.NewRecorder()
			start := time.Now()
			p.proxyToNode(w, r, addr, "api")
			if hits.Load() != 0 || w.Code == 200 {
				t.Fatalf("unavailable permission dispatched: hits=%d status=%d", hits.Load(), w.Code)
			}
			if mode == "denied" && w.Code != 403 {
				t.Fatal("denied permission status", w.Code)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("initial permission check exceeded bound")
			}
		})
	}
}
