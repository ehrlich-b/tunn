//go:build candidatefixture

package tunn

import (
	"context"
	"net"
	"net/http"
)

// CandidateFixturePublishHandler exposes only the existing embedded dial seam
// to offline integration fixtures. This symbol is absent from normal builds.
// Public PublishHandler acceptance still requires the ordinary-host gate.
func CandidateFixturePublishHandler(ctx context.Context, handler http.Handler, options Options, dial func(context.Context, string, string) (net.Conn, error)) (*Tunnel, error) {
	if handler == nil || options.Origin != "" {
		return nil, invalid("fixture requires a handler and empty Origin")
	}
	options.Origin = "http://sdk-handler.invalid"
	core, name, err := publisher(options)
	if err != nil {
		return nil, err
	}
	core.DialContext = dial
	origin := &handlerOrigin{handler: handler, incoming: make(chan net.Conn), done: make(chan struct{}), served: make(chan struct{})}
	return startTunnel(ctx, options, core, name, origin)
}
