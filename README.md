# tunn

Expose localhost to the internet. Share with specific people.

```bash
tunn 8080
```

```
https://abc123.tunn.to -> localhost:8080
```

## Install

```bash
# macOS / Linux
curl -fsSL https://tunn.to/install.sh | sh

# Or build from source
make build
./bin/tunn
```

## Usage

```bash
# Login with Google (one-time)
tunn login

# Expose localhost:8080
tunn 8080

# Share with specific people
tunn 8080 --allow alice@gmail.com,bob@company.com
```

Visitors to your tunnel URL are prompted to log in with Google. If their email is on the allow list, they get through. Otherwise, access denied.

## How It Works

```
Browser -> tunn.to -> your laptop
```

Your laptop connects to tunn.to over a persistent tunnel. When someone visits your tunnel URL, the request is forwarded to your localhost.

- TLS terminated at tunn.to
- Supports HTTP/2 and HTTP/3

## Commands

```bash
tunn <port>              # Tunnel localhost:<port>
tunn <host:port>         # Tunnel any host:port
tunn <url>               # Tunnel any URL
tunn login               # Authenticate with Google
tunn --help              # Show help
```

## Options

```bash
tunn 8080 --allow alice@gmail.com   # Share with specific emails
tunn 8080 -id=myapp                 # Custom tunnel ID (myapp.tunn.to)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and architecture details.

## License

MIT
