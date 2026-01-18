# tunn

Share localhost like a Google Doc.

```bash
tunn 8080
```

```
https://abc123.tunn.to → localhost:8080
```

Share with specific people:

```bash
tunn 8080 --allow alice@gmail.com,bob@company.com
```

Visitors log in with GitHub. If they're on your list, they're in. Otherwise, access denied.

## Install

```bash
curl -fsSL https://tunn.to/install.sh | sh
```

Or build from source: `make build`

## Usage

```bash
tunn login                    # One-time GitHub auth
tunn 8080                     # Expose localhost:8080
tunn 3000 --allow @company.com  # Allow entire domain
tunn 8080 -id=myapp           # Custom URL (myapp.tunn.to)
```

## Self-Host

Run your own tunn server:

```bash
tunn -mode=host -domain=tunnel.yourcompany.com
```

See [docs/self-hosting.md](docs/self-hosting.md) for details.

## How It Works

Your laptop connects to tunn.to over a persistent tunnel. When someone visits your tunnel URL, the request is forwarded to your localhost.

- TLS terminated at tunn.to (or your server)
- HTTP/2 and HTTP/3 support
- Email-based access control

## Development

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for build instructions, architecture, and contribution guidelines.

## License

MIT
