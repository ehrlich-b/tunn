# Always-on publishers and SSH clients

On a relay supporting durable device credentials, run `tunn login` independently
on the publisher and each laptop. Existing logins remain valid until their
24-hour expiry; run login once with the updated CLI to obtain renewable device
credentials. Never copy the credential files between machines.

Publish forge's SSH port using the updated binary:

```sh
tunn tcp --account-only --name forge-ssh 127.0.0.1:22
```

Use account authentication from the laptop in `~/.ssh/config`:

```sshconfig
Host forge
    HostName forge-ssh
    User YOUR_FORGE_USER
    ProxyCommand tunn connect --stdio --account forge-ssh
```

A publisher refreshes before expiry and sends its new access token on the
existing tunnel; live SSH connections remain open during successful renewal.
The laptop obtains a current token before opening each CONNECT. If the relay
returns 401, it renews once and retries before reading any SSH bytes. A local
listener (`tunn connect --account --listen 127.0.0.1:2222 forge-ssh`) also obtains
a current token for each new connection. An already authorized laptop session
can drain normally after device revocation; a revoked publisher loses its lease
and connections within five minutes with synchronized relay clocks (up to one additional minute of permitted relay clock skew). A login-server outage lasting past the
publisher lease expiry closes the tunnel rather than allowing indefinite access.

Open `https://YOUR_RELAY/account/devices` in a logged-in browser to list devices
and revoke a lost laptop or compromised publisher. Device credentials permit
publishing and connecting; account administration requires a browser session or
an existing unexpired management credential. They cannot change billing or
manage other devices. Self-hosted `--secret` and endpoint-token connections keep
their existing authentication behavior.

The CLI stores `credentials.json` (authoritative) and `token` (compatibility
mirror) in `~/.tunn`, or the absolute directory in `TUNN_CONFIG_DIR`. Files are
atomically replaced with mode 0600; the directory is mode 0700. Refreshes use
an OS file lock so multiple publishers and SSH commands on one machine can
safely share the same login. Credentials are bound to their original HTTPS
relay; use separate config directories for different relays. On Windows the
user must also protect the directory with a private user ACL.

Temporary refresh errors explain how to check connectivity and retry. A revoked
or reused credential reports `run tunn login on this device`; reauthorize on
that machine. A lost refresh response can recover the same rotation for 60
seconds. A crash or outage past that recovery window requires a fresh login.
An always-on publisher needs outbound HTTPS access to its login relay in
addition to the tunnel control connection. Update the relay before its clients;
new clients retain legacy access-token behavior when an old relay returns no
refresh credential.
