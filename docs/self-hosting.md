# Self-Hosting Guide

tunn is fully self-hostable. This guide covers running your own tunnel server.

## Requirements

1. **A server with a public IP** - VPS, cloud VM, or on-prem with port forwarding
2. **A domain with wildcard DNS** - `*.tunnel.yourcompany.com` pointing to your server
3. **TLS certificates** - Wildcard cert for `*.tunnel.yourcompany.com`

## Quick Start (Single Node)

### 1. Get the binary

```bash
# Download latest release
curl -L https://github.com/ehrlich-b/tunn/releases/latest/download/tunn-linux-amd64 -o tunn
chmod +x tunn
```

Or build from source:
```bash
git clone https://github.com/ehrlich-b/tunn.git
cd tunn
make build
```

### 2. Set up DNS

Add a wildcard A record pointing to your server:
```
*.tunnel.yourcompany.com  A  203.0.113.10
```

### 3. Get TLS certificates

Using Let's Encrypt with certbot:
```bash
certbot certonly --manual --preferred-challenges dns \
  -d "tunnel.yourcompany.com" \
  -d "*.tunnel.yourcompany.com"
```

You'll need to add a DNS TXT record to verify ownership.

### 4. Configure and run

```bash
export TUNN_ENV=prod
export TUNN_DOMAIN=tunnel.yourcompany.com
export TUNN_CERT_FILE=/etc/letsencrypt/live/tunnel.yourcompany.com/fullchain.pem
export TUNN_KEY_FILE=/etc/letsencrypt/live/tunnel.yourcompany.com/privkey.pem
export TUNN_LOGIN_NODE=true
export TUNN_CLIENT_SECRET=your-secret-key-here
export TUNN_JWT_SECRET=another-random-secret

./tunn -mode=host
```

### 5. Connect a tunnel

On your laptop:
```bash
./tunn 8080 --server tunnel.yourcompany.com:443 --secret your-secret-key-here
```

## Authentication Options

### Option A: Client Secret (Simplest)

A single shared secret for all users. Good for small teams.

**Server:**
```bash
export TUNN_CLIENT_SECRET=my-shared-secret
```

**Client:**
```bash
tunn 8080 --secret my-shared-secret
```

### Option B: Per-User Tokens (users.yaml)

Individual tokens per user. Better for larger teams.

**Create users.yaml:**
```yaml
users:
  - email: alice@company.com
    token: alice-secret-token-here
  - email: bob@company.com
    token: bob-secret-token-here
```

**Server:**
```bash
export TUNN_USERS_FILE=/path/to/users.yaml
```

**Client:**
```bash
tunn 8080 --secret alice-secret-token-here
```

### Option C: GitHub OAuth + Magic Link (Full tunn.to experience)

Requires GitHub OAuth app and SMTP for magic link emails.

**1. Create GitHub OAuth App:**
- Go to GitHub Settings -> Developer settings -> OAuth Apps
- Set callback URL to `https://tunnel.yourcompany.com/auth/callback`

**2. Configure SMTP** (for magic link auth - users without GitHub):
```bash
export TUNN_SMTP_HOST=smtp.mailgun.org  # Or your SMTP provider
export TUNN_SMTP_PORT=587
export TUNN_SMTP_USER=postmaster@tunnel.yourcompany.com
export TUNN_SMTP_PASSWORD=your-smtp-password
export TUNN_SMTP_FROM=noreply@tunnel.yourcompany.com
```

**3. Configure server:**
```bash
export TUNN_GITHUB_CLIENT_ID=your-github-client-id
export TUNN_GITHUB_CLIENT_SECRET=your-github-client-secret
export TUNN_JWT_SECRET=random-secret-for-signing-jwts
# Plus SMTP vars from step 2
```

**4. Users authenticate:**
```bash
# Via CLI (GitHub OAuth device flow)
tunn login --server tunnel.yourcompany.com:443
tunn 8080

# Via browser (GitHub or magic link)
# Users visiting tunnels get redirected to login page
# They can choose GitHub or enter email for magic link
```

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `TUNN_ENV` | `prod` for production |
| `TUNN_DOMAIN` | Your tunnel domain (e.g., `tunnel.yourcompany.com`) |
| `TUNN_CERT_FILE` | Path to TLS certificate |
| `TUNN_KEY_FILE` | Path to TLS private key |
| `TUNN_LOGIN_NODE` | Set to `true` for single-node deployments |

### Authentication (pick one)

| Variable | Description |
|----------|-------------|
| `TUNN_CLIENT_SECRET` | Shared secret for all clients |
| `TUNN_USERS_FILE` | Path to users.yaml for per-user tokens |
| `TUNN_GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `TUNN_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |

### SMTP (for magic link auth)

| Variable | Description |
|----------|-------------|
| `TUNN_SMTP_HOST` | SMTP server hostname |
| `TUNN_SMTP_PORT` | SMTP port (default: 587) |
| `TUNN_SMTP_USER` | SMTP username |
| `TUNN_SMTP_PASSWORD` | SMTP password |
| `TUNN_SMTP_FROM` | From address for emails |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNN_HTTP2_ADDR` | `:8443` | HTTP/2 listen address |
| `TUNN_HTTP3_ADDR` | `:8443` | HTTP/3 listen address |
| `TUNN_JWT_SECRET` | (required for OAuth) | Secret for signing JWTs |
| `TUNN_PUBLIC_MODE` | `false` | Disable all auth (testing only) |
| `TUNN_DB_PATH` | `/data/tunn.db` | SQLite database path |
| `TUNN_WELL_KNOWN_KEY` | `tunn-free-v1-2025` | Key clients use to create tunnels |

## Running as a Service

### systemd

Create `/etc/systemd/system/tunn.service`:

```ini
[Unit]
Description=tunn reverse tunnel server
After=network.target

[Service]
Type=simple
User=tunn
Environment=TUNN_ENV=prod
Environment=TUNN_DOMAIN=tunnel.yourcompany.com
Environment=TUNN_CERT_FILE=/etc/letsencrypt/live/tunnel.yourcompany.com/fullchain.pem
Environment=TUNN_KEY_FILE=/etc/letsencrypt/live/tunnel.yourcompany.com/privkey.pem
Environment=TUNN_LOGIN_NODE=true
Environment=TUNN_CLIENT_SECRET=your-secret
Environment=TUNN_JWT_SECRET=another-secret
ExecStart=/usr/local/bin/tunn -mode=host
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable tunn
sudo systemctl start tunn
```

### Docker

```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY . .
RUN make build

FROM alpine:latest
COPY --from=builder /app/bin/tunn /usr/local/bin/tunn
ENTRYPOINT ["tunn", "-mode=host"]
```

```bash
docker run -d \
  -p 8443:8443 \
  -v /etc/letsencrypt:/certs:ro \
  -e TUNN_ENV=prod \
  -e TUNN_DOMAIN=tunnel.yourcompany.com \
  -e TUNN_CERT_FILE=/certs/live/tunnel.yourcompany.com/fullchain.pem \
  -e TUNN_KEY_FILE=/certs/live/tunnel.yourcompany.com/privkey.pem \
  -e TUNN_LOGIN_NODE=true \
  -e TUNN_CLIENT_SECRET=your-secret \
  tunn
```

## Certificate Renewal

If using Let's Encrypt, set up automatic renewal:

```bash
# In crontab
0 0 1 * * certbot renew --quiet && systemctl reload tunn
```

## Firewall Configuration

Open these ports:

| Port | Protocol | Purpose |
|------|----------|---------|
| 443 or 8443 | TCP | HTTP/2 (gRPC + HTTPS) |
| 443 or 8443 | UDP | HTTP/3 (QUIC) - optional |

## Monitoring

Check tunnel is running:
```bash
curl -k https://tunnel.yourcompany.com/
```

Check logs:
```bash
journalctl -u tunn -f
```

## Multi-Node Setup

For high availability, see [Multi-Node Architecture](./multi-node.md).
