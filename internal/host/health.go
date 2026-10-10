package host

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"google.golang.org/grpc/connectivity"
)

const (
	listenerHTTP2 = 1 << iota
	listenerHTTP3
	listenerInternal
	listenerSSH
	listenerHTTP01
)

func (p *ProxyServer) listenerStarted(bit uint32) {
	state := p.listenerState.Or(bit) | bit
	if state == p.requiredListeners.Load() && !p.stopping.Load() {
		common.LogInfo("proxy listeners ready", "http2", p.HTTP2Addr, "http3", p.HTTP3Addr,
			"internal_grpc", p.config.InternalGRPCPort, "domain", p.Domain, "env", p.config.Environment)
	}
}

func (p *ProxyServer) ready(ctx context.Context) bool {
	required := p.requiredListeners.Load()
	if required == 0 || p.stopping.Load() || p.listenerState.Load() != required || p.storage == nil || !p.storage.Available() {
		return false
	}
	if health, ok := p.storage.(interface{ CheckHealth(context.Context) error }); ok {
		return health.CheckHealth(ctx) == nil
	}
	if !p.isLoginNode {
		p.loginNodeMu.RLock()
		defer p.loginNodeMu.RUnlock()
		return p.loginNodeConn != nil && p.loginNodeConn.GetState() == connectivity.Ready
	}
	return true
}

func (p *ProxyServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	code, body := http.StatusOK, "ok"
	if r.URL.Path == "/readyz" {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if !p.ready(ctx) {
			code, body = http.StatusServiceUnavailable, "not ready"
		}
	}
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		_, _ = fmt.Fprint(w, body)
	}
}
