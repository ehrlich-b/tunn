package host

import (
	"context"
	"net/http"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
)

// Watch existing termination hooks, including idle connections. A body charge
// alone cannot notice suspension of an idle WS/CONNECT or an SSE wait.
// One waiter per admitted request; it ends with that request. Domain/quota
// enforcement can share AccountStatusLookup and CloseAccountStreams.
func (p *ProxyServer) watchAccountRequest(r *http.Request, t *TunnelConnection, admitted *storage.Account) (*http.Request, func()) {
	lookup, ok := p.storage.(storage.AccountStatusLookup)
	if !ok || t.accountQuotaExempt || t.AccountID == "" || admitted == nil {
		return r, func() {}
	}
	ctx, cancel := context.WithCancel(r.Context())
	go func() {
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				checkCtx, stop := context.WithTimeout(ctx, 5*time.Second)
				status, err := lookup.LookupAccountStatus(checkCtx, t.AccountID)
				stop()
				if err != nil || status == nil || status.State != "active" || status.Version != admitted.OperationalVersion {
					cancel()
					if err != nil || status == nil || status.State != "active" {
						t.CloseAccountStreams()
					}
					_ = r.Body.Close()
					return
				}
			}
		}
	}()
	return r.WithContext(ctx), cancel
}
func (t *TunnelConnection) CloseAccountStreams() { t.closePendingConnections() }
func (p *ProxyServer) currentTime() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}
