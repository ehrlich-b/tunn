package host

import (
	"context"

	"github.com/ehrlich-b/tunn/internal/common"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
)

// InternalServer implements the gRPC InternalService
type InternalServer struct {
	internalv1.UnimplementedInternalServiceServer
	tunnelServer *TunnelServer
	publicAddr   string
}

// NewInternalServer creates a new gRPC internal server
func NewInternalServer(tunnelServer *TunnelServer, publicAddr string) *InternalServer {
	return &InternalServer{
		tunnelServer: tunnelServer,
		publicAddr:   publicAddr,
	}
}

// FindTunnel implements the RPC for finding a tunnel on another node
func (s *InternalServer) FindTunnel(ctx context.Context, req *internalv1.FindTunnelRequest) (*internalv1.FindTunnelResponse, error) {
	tunnelID := req.GetTunnelId()
	common.LogInfo("internal request to find tunnel", "tunnel_id", tunnelID)

	if _, exists := s.tunnelServer.GetTunnel(tunnelID); exists {
		common.LogInfo("tunnel found locally", "tunnel_id", tunnelID)
		return &internalv1.FindTunnelResponse{
			Found:       true,
			NodeAddress: s.publicAddr,
		}, nil
	}

	common.LogInfo("tunnel not found locally", "tunnel_id", tunnelID)
	return &internalv1.FindTunnelResponse{
		Found: false,
	}, nil
}
