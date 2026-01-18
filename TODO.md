# TODO

## Pre-Launch

### Code

- [ ] **Cache invalidation on cross-node 503** - When `proxyToNode` gets 503, delete cache entry and re-probe. Location: `internal/host/webproxy.go`

### Manual Setup

- [ ] GitHub OAuth App - Create in GitHub settings, get client ID/secret
- [ ] SMTP provider - For magic link emails (AWS SES, Resend, etc.)
- [ ] Fly.io deploy + DNS
- [ ] Stripe Payment Link - Set `TUNN_STRIPE_CHECKOUT_URL`

## Post-Launch

- [ ] Windows support
- [ ] Homebrew formula
- [ ] macOS code signing (if friction complaints pile up)

## Future

- **V1.2:** Enterprise SSO (Google Workspace, Entra ID, Okta, SAML)
- **V1.3:** UDP Relay (both ends run tunn, JWT auth)
- **V1.4:** Custom domains + raw mode (end-to-end encryption)
