# tunn and Tailscale

Use Tailscale to connect your own devices privately in a tailnet. Use tunn to
give a local app or MCP tool a public HTTPS URL with a chosen audience: you,
invited people, or an AI client. A public address does not mean anonymous access.
Tunn is private by default; `--public` opens it to everyone.
([Tailscale overview][ts-overview]; tunn: [publication flags][flags],
[HTTP publisher][main], [edge access checks][edge].)

Tailscale sources below were read on **2026-10-16**. Tailscale behavior here is
from those public docs, not a live tailnet test. Tunn behavior was checked against
the linked code; the local checks at the end need no accounts.

## Run both on one machine

Keep Tailscale connected. With your app on port 3000 and tunn installed:

```sh
tunn login
tunn 3000 --allow alex@example.com
```

Replace the email and send Alex the printed HTTPS URL. Alex signs in using a
method offered by the relay, such as Google, an email link or company sign-in
where configured. Keep the app and tunn running. Tunn opens an outbound TLS/gRPC
connection to its relay and dials your app locally; it does not need an inbound
port on your Tailscale interface. Running both does not create a port conflict.
Your network must still allow the relay connection.
(Tunn: [login][login], [email login][magic], [client connection][client],
[origin transport][origin], [edge access checks][edge].)

## Share a home server from another tailnet device

Suppose `home-server` is a MagicDNS name and its app listens on port 8080 on an
address reachable through Tailscale. On the machine that will run tunn, first
check the upstream, then publish it:

```sh
curl --connect-timeout 5 http://home-server:8080/
tunn http://home-server:8080 --allow alex@example.com
```

MagicDNS resolves machine names for tailnet devices. Tailnet ACLs or grants must
allow this publishing machine to reach the server's port. If the curl fails,
fix DNS, the app's listening address, or that policy before publishing.
([MagicDNS][ts-dns], [access policy][ts-access]; tunn: `normalizeTargetURL` in
[main.go][main] and [origin transport][origin].)

The request path is visitor → tunn relay → publishing machine → home server.
The visitor needs tunn permission, not tailnet membership. The home server sees
the publisher's network connection. **You are giving the chosen audience access
to that app through your network access.** Tunn forwards the app's HTTP paths;
this does not give visitors a general network route to every tailnet device.
It can still expose everything the app itself can read or do. Keep app login
and permissions where needed. Using `--public` would allow anonymous requests.
(Tunn: [HTTP forwarding][http-stream], [origin transport][origin],
[edge access checks][edge].)

For an HTTP MCP server at `http://home-server:3000/mcp`, use this instead:

```sh
tunn mcp --allow alex@example.com http://home-server:3000/mcp
```

Put the printed public `/mcp` URL in the AI client's connector settings. Sign in
and approve its access. Tunn implements OAuth discovery, client registration,
PKCE, consent and tokens for MCP. Hosted AI-client interoperability still needs
verification; follow the [connector guide](mcp-to-claude.md) for its current
acceptance status. `--tools` currently filters stdio MCP commands only; restrict
an HTTP MCP server's tools at the server.
(Tunn: `parseMCPFlags` and `runMCP` in [main.go][main], [MCP OAuth][oauth].)

## Funnel or tunn?

For a public local web server, Tailscale's documented command is
`tailscale funnel 3000`. For access confined to the tailnet, use Tailscale Serve.
([Funnel][ts-funnel].)

| Question | Tailscale Funnel | tunn |
| --- | --- | --- |
| Who can visit? | Anyone with the URL; no visitor Tailscale sign-in. App authentication is up to the app. [Sharing comparison][ts-sharing] | Private by default; invite emails or `@example.com`, or choose `--public`. [Flags][flags], [edge checks][edge] |
| Who may publish? | The tailnet's `funnel` node attribute controls this, not visitor access. [Funnel][ts-funnel] | Publisher authentication is separate from visitor permission. [HTTP publisher][main] |
| MCP and OAuth? | The documented feature publishes a service; it does not document providing MCP OAuth. Supply that in your app. [Funnel][ts-funnel] | MCP adapter plus OAuth discovery, consent and tokens. [Publisher][main], [OAuth][oauth] |
| Custom domain? | Only names under the tailnet's `*.ts.net` domain. [Funnel][ts-funnel] | Pro supports custom domains after DNS proof and certificate provisioning. [Domain CLI][domain-cli], [registry][domains] |
| Limits? | TLS only; public ports 443, 8443 or 10000; fixed bandwidth limits. Requires MagicDNS, HTTPS and Tailscale 1.38.3+. [Funnel][ts-funnel] | Default Free/Pro: 5/25 concurrent tunnels, 10/500 GB monthly and 1M/10M monthly admissions; deployments may set lower quotas. [Tunnel limits][storage], [bytes][limits], [metering][metering], [configured limits][revenue] |

## Visit from inside the tailnet

Open the same printed tunn HTTPS URL and sign in as usual. Tailnet membership
does not bypass tunn's edge checks or make the URL private. Going directly to
`http://home-server:8080` uses the tailnet path and its policy instead.
(Tunn: [edge access checks][edge]; [Tailscale access policy][ts-access].)

## Use both for SSH

Use Tailscale for private administration, for example `ssh deploy@home-server`
with MagicDNS and network access allowed. If you enable Tailscale SSH, its
server handles port 22 on the Tailscale IP and requires both network and SSH
policy permission. ([MagicDNS][ts-dns], [Tailscale SSH][ts-ssh].)

You can also publish the web app over OpenSSH to tunn, from a machine that can
reach `home-server:8080`:

```sh
ssh -T -p 443 -o ExitOnForwardFailure=yes \
  -R0:home-server:8080 tunn.to -- --allow alex@example.com --expire 30m
```

Here SSH carries app traffic to tunn; it does not log you into the home server.
The local SSH client reaches the target. Keep the session open. The relay must
have its SSH entry point enabled; an unlinked key requires an explicit allow-list
and has a 30-minute maximum. (Tunn: [SSH command handling][ssh-code] and
[SSH forwarding][ssh-forward]; [SSH API](../ssh-api.md).)

For shell access without joining the tailnet, publish an ordinary local SSH
server on the home server itself:

```sh
# Home server, logged into tunn:
tunn tcp --account-only --name home-ssh --allow alex@example.com 127.0.0.1:22
# Alex's machine, logged into tunn as alex@example.com:
ssh -o 'ProxyCommand=tunn connect --account --stdio home-ssh' deploy@home-ssh
```

Alex still needs the origin SSH host key verified and an OS login/key for
`deploy`. A tunnel grant does not grant an OS login. Loopback port 22 reaches
the ordinary SSH server, not Tailscale SSH on the Tailscale IP. For an OpenSSH-only
recipient, see the [SSH API](../ssh-api.md) jump pilot and its prerequisites.
(Tunn: `parseTCPFlags`, `parseConnectFlags`, `runConnect` in [main.go][main],
[CONNECT transport][connect]; [Tailscale SSH][ts-ssh].)

## Pitfalls

- **Two entrances.** A Funnel URL or direct app URL can remain accessible after
  you restrict tunn. Audit each entrance. Funnel and Serve cannot share the same
  listening port: the last configuration makes that port public or private.
  ([Funnel][ts-funnel]; tunn: [edge checks][edge].)
- **ACLs are not visitor rules.** Tailnet policy governs the publisher-to-server
  connection. It does not distinguish the people arriving through that publisher's
  tunn endpoint. Set tunn's audience too. Funnel's publisher permission likewise
  does not restrict visitors. ([Access policy][ts-access],
  [sharing comparison][ts-sharing]; tunn: [origin transport][origin], [edge][edge].)
- **Share the right URL.** A printed `http://home-server:8080` is the upstream,
  not the visitor link. Use tunn's printed HTTPS URL. MagicDNS machine names are
  for tailnet resolution. Configure app redirects and absolute asset URLs to use
  the public origin; tunn passes upstream `Location` redirects through unchanged.
  ([MagicDNS][ts-dns]; tunn: [output][client], [redirect handling][redirects].)
- **Exit nodes change the route.** Tailscale normally leaves public internet
  traffic alone; an exit node routes that traffic, so tunn's relay connection may
  use it too. If tunn fails after switching exit nodes, check that node's internet
  reachability and DNS. Exit nodes also disable local LAN access by default;
  enable it only if your upstream needs it. They do not change tunn's audience.
  ([Exit nodes][ts-exit]; tunn: [relay dialer][relay], [edge][edge].)

## What was checked locally

Account-free Go tests exercise target URL parsing, HTTP MCP URL parsing, local
HTTP forwarding, origin dial isolation and unchanged redirect headers
(`TestCLIRejectsInvalidPortsBeforeLogin`, `TestParseMCPHTTPURL`,
`TestHandleHttpRequest`, `TestOriginPoolDialIsolation`,
`TestOriginRedirectPassthrough`). These check tunn's mechanics with local test
servers, not Tailscale connectivity. Funnel, MagicDNS, exit nodes, real sign-in
and hosted AI connectors were not exercised here.

[ts-overview]: https://tailscale.com/docs/concepts/what-is-tailscale
[ts-funnel]: https://tailscale.com/docs/features/tailscale-funnel
[ts-sharing]: https://tailscale.com/docs/reference/funnel-vs-sharing
[ts-dns]: https://tailscale.com/docs/features/magicdns
[ts-access]: https://tailscale.com/docs/manage
[ts-ssh]: https://tailscale.com/docs/features/tailscale-ssh
[ts-exit]: https://tailscale.com/docs/features/exit-nodes
[main]: ../../main.go
[flags]: ../../internal/cliopts/serve.go
[client]: ../../internal/client/serve.go
[origin]: ../../internal/client/origin_pool.go
[http-stream]: ../../internal/client/http_stream.go
[edge]: ../../internal/host/webproxy.go
[login]: ../../internal/client/login.go
[magic]: ../../internal/host/magiclink.go
[oauth]: ../../internal/host/mcp_oauth.go
[domain-cli]: ../../domains_cli.go
[domains]: ../../internal/domains/registry.go
[storage]: ../../internal/storage/storage.go
[limits]: ../../internal/host/limits.go
[metering]: ../../internal/metering/store.go
[revenue]: ../../internal/host/revenue.go
[ssh-code]: ../../internal/host/ssh.go
[ssh-forward]: ../../internal/sshfront/server.go
[redirects]: ../../internal/client/redirect_passthrough_test.go
[relay]: ../../internal/relaytransport/transport.go
[connect]: ../../internal/client/connect.go
