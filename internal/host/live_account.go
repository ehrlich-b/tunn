package host

import (
	"context"
	"fmt"

	"github.com/ehrlich-b/tunn/internal/storage"
)

// Connection ownership is immutable. Resolve its UUID through shared storage so
// merges and billing changes take effect on every node without a reconnect.
func (p *ProxyServer) currentTunnelAccount(ctx context.Context, tunnel *TunnelConnection) (*storage.Account, error) {
	if tunnel.accountQuotaExempt || tunnel.CreatorEmail == "" && tunnel.AccountID == "" {
		return nil, nil
	}
	if tunnel.AccountID == "" || p.storage == nil || !p.storage.Available() {
		return nil, fmt.Errorf("account storage unavailable")
	}
	account, err := p.storage.GetAccount(ctx, tunnel.AccountID)
	if err != nil {
		return nil, err
	}
	if account == nil || account.ID == "" {
		return nil, fmt.Errorf("unknown tunnel account")
	}
	return account, nil
}
