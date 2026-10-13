package host

import (
	"context"
	"errors"
	"fmt"

	"github.com/ehrlich-b/tunn/internal/storage"
)

var errUnknownTunnelAccount = errors.New("unknown tunnel account")

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
		return nil, errUnknownTunnelAccount
	}
	return account, nil
}
