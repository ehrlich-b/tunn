# OpenClaw through tunn — guide draft

Not affiliated with OpenClaw.

This draft covers browser access to a local Gateway through an HTTPS tunnel.
The local WebSocket fixture is the implementation regression test; real
OpenClaw, mobile browsers, sleep/wake, and native-node pairing still need the
manual checks below before advertising compatibility.

1. **Keep the Gateway private and authenticated.** Run OpenClaw's Gateway on
   loopback port 18789, with token or password auth enabled. Set the full public
   origin you intend to use in `gateway.controlUi.allowedOrigins`, for example:

   ```json5
   {
     gateway: {
       port: 18789,
       bind: "loopback",
       auth: { mode: "token", token: "<your-existing-gateway-token>" },
       controlUi: { allowedOrigins: ["https://myclaw.tunn.to"] }
     }
   }
   ```

   Apply changes using OpenClaw's normal configuration workflow. Its Gateway
   serves HTTP and WebSockets on the same port; the browser's gateway secret is
   sent in the WebSocket connection message. Keep that auth enabled.
   [Gateway configuration](https://docs.openclaw.ai/gateway/config-gateway),
   [dashboard authentication](https://docs.openclaw.ai/web/dashboard).

2. **Start an email-restricted tunnel on the same machine.** Install/build a
   tunn version with WebSocket support, then run:

   ```bash
   tunn login
   tunn 18789 --id=myclaw --allow=you@example.com
   ```

   The relay must support WebSockets too. A named URL requires permission to
   use that name. If tunn assigns a random URL, use its actual full HTTPS origin
   in `allowedOrigins` and update it whenever the URL changes. Add other emails
   to `--allow` only when they should reach the Gateway.

3. **Open the printed HTTPS URL and sign in.** Use a personal account with
   an allowed email, using Google or an email link where offered by the relay.
   Then enter the existing Gateway token/password in the
   Control UI. Its WebSocket connects over `wss://` using the tunn session
   cookie. Complete OpenClaw's normal device-pairing approval if prompted.

TLS terminates at the tunn relay, which can see HTTP and WebSocket traffic.
The email gate and Gateway authentication protect separate layers. Keep
`gateway.bind` on loopback and don't disable Gateway auth or origin checking.
`tunn` preserves the public Host/Origin and sets clean forwarded headers; see
[the exact header contract](../how-it-works.md#websocket-upgrades).

## Native clients and the CLI

Clients that can attach headers to a WebSocket handshake can use an opt-in
endpoint token instead of a browser session:

```bash
tunn 18789 --id=myclaw --allow=you@example.com --bearer
tunn token myclaw
```

Set `Tunn-Authorization: Bearer <tunn-endpoint-token>` on the handshake and
continue using the separate Gateway credential in OpenClaw's connection
message. For supported OpenClaw CLI/app versions,
`gateway.remote.edgeAuth` supplies edge headers scoped to the configured WSS
URL. Header values support secret providers; follow the
[remote-access documentation](https://docs.openclaw.ai/gateway/remote#gateway-behind-an-identity-aware-proxy)
for your version. Native iOS/Android node support is unverified: this guide does
not claim those apps expose a compatible custom-header setting.

Rotate with `tunn token --rotate myclaw`. After the running publisher sends the
new digest, the old token fails HTTP/upgrades and its existing WebSockets
close. Update the client credential and reconnect. Cookie-authenticated browser
connections remain available. Treat the tunn token as a secret; don't place it
in URLs or browser local storage.

For HTTP APIs or native clients that send an upstream `Authorization` header,
`--require-upstream-auth` can require that header after tunn's token is stripped.
It checks presence; OpenClaw must still validate the credential. **Do not use
this flag for the browser Control UI:** its Gateway auth travels inside the
WebSocket message. tunn does not inspect that message or prove the Gateway's
local auth configuration.

## Manual acceptance before launch

Use a personal, non-production fixture and an allowed test email. Verify:

- Dashboard load, WebSocket connection, and a chat interaction in desktop,
  iOS Safari, and Android Chrome.
- A denied email and an unsigned upgrade never reach the Gateway.
- Thirty minutes idle remains connected with keepalive; sleep/wake reconnects.
- A large attachment fits both the configured WebSocket message limit and
  OpenClaw's own limits. Raise `--ws-max-message-size` only when needed.
- CLI edge headers work; rotation denies the old token and closes its socket.
- Native-node pairing separately, if the installed app can send edge headers.

No live OpenClaw or tunn.to test is part of the local automated suite.
