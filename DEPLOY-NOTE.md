# Publishing status checks later

Do not enable this until a reachable, operator-controlled HTTPS origin has been provisioned for the collector. An existing observer may use a different format and cannot serve as the collector. On the collector host, install the built `tunn` binary at `%h/.local/bin/tunn`, create `%h/.local/share/tunn-status` with mode 700, and use this user unit at `~/.config/systemd/user/tunn-status.service`:

```ini
[Unit]
Description=tunn public status collector
After=network-online.target

[Service]
ExecStart=%h/.local/bin/tunn status serve --listen 127.0.0.1:8091 --db %h/.local/share/tunn-status/status.db --probe https://tunn.to
Restart=on-failure
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=default.target
```

Enable user lingering if needed, then start the user service. Put a read-only HTTPS reverse proxy in front of loopback port 8091, exposing only `/status` and `/status.json`. Provision DNS, TLS, firewall and reachability from every Fly relay; Fly's loopback is not the collector host's loopback. The relay needs a response within three seconds. Use a dedicated status origin, for example `https://status-origin.tunn.to`, and configure the relay with:

```sh
TUNN_STATUS_URL=https://status-origin.tunn.to
```

The hostname is a proposed origin and must resolve to the provisioned proxy before setting it. If the collector host's connection drops, the relay cannot reach the collector and shows status unknown (503); after reconnection, missing observations remain gaps, not healthy minutes. A status page on tunn.to also cannot be reached when tunn.to ingress is down. See `docs/status.md` for verification and incident handling.
