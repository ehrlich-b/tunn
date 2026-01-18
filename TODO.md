# TODO

## Pre-Launch

### Manual Setup

- [x] GitHub OAuth App - Created
- [ ] Resend - Sign up, add tunn.to domain, get API key
- [ ] Certbot - `sudo certbot certonly --manual --preferred-challenges dns -d tunn.to -d '*.tunn.to'`
- [ ] Fly deploy - `make fly-create && make fly-init && make fly-secrets && make fly-certs && make fly-deploy`
- [ ] DNS - Point tunn.to and *.tunn.to to Fly IPs (get with `make fly-status`)
- [ ] Stripe Payment Link - Set `TUNN_STRIPE_CHECKOUT_URL` (can do post-launch)

## Post-Launch

- [ ] Windows support
- [ ] Homebrew formula
- [ ] macOS code signing (if friction complaints pile up)

## Future

- **V1.2:** Enterprise SSO (Google Workspace, Entra ID, Okta, SAML)
- **V1.3:** UDP Relay (both ends run tunn, JWT auth)
- **V1.4:** Custom domains + raw mode (end-to-end encryption)
