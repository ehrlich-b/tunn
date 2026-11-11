package storage

import (
	"context"

	"github.com/ehrlich-b/tunn/internal/common"
	"google.golang.org/grpc/metadata"
)

// Metadata keeps this optional attribution compatible with older login nodes;
// both send and receive boundaries normalize it before any database write.
const funnelSourceMetadata = "tunn-signup-source"

func outgoingFunnelSource(ctx context.Context) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set(funnelSourceMetadata, common.FunnelSource(ctx))
	return metadata.NewOutgoingContext(ctx, md)
}

// IncomingFunnelSource restores the normalized channel across the login-node RPC.
func IncomingFunnelSource(ctx context.Context) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	source := ""
	if values := md.Get(funnelSourceMetadata); len(values) > 0 {
		source = values[0]
	}
	return common.WithFunnelSource(ctx, source)
}
