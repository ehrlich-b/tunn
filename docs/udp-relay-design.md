# UDP Relay Design (V1.x Pro Feature)

**Problem:** User is trapped on a restrictive network (school, corporate, hotel WiFi) that blocks UDP. They need to get WireGuard/UDP traffic out to reach their home network or work VPN.

**Solution:** UDP relay over gRPC. Both peers connect to tunn.to over TCP:443 (HTTPS, almost never blocked), and tunn relays UDP packets between them.

## Use Case

```
┌─────────────────┐                              ┌─────────────────┐
│  Intern laptop  │                              │  Home server    │
│  (school WiFi)  │                              │  (WireGuard)    │
│                 │                              │                 │
│  WireGuard ─────┼──► tunn relay ──────────────►│ tunn relay ─────┼──► WireGuard
│  localhost:51820│    (gRPC/TCP:443)            │                 │    localhost:51820
└─────────────────┘            │                 └─────────────────┘
                               │
                        ┌──────▼──────┐
                        │   tunn.to   │
                        │  UDP relay  │
                        │  (Pro tier) │
                        └─────────────┘
```

School network blocks UDP but allows HTTPS. tunn relay encapsulates UDP in gRPC, tunnels over TCP:443.

## How It Works

### Setup

**Home server (has open internet):**
```bash
tunn relay 51820 --id=home-wg --peer=intern-wg
```
- Exposes local WireGuard (localhost:51820)
- Accepts relay traffic from peer `intern-wg`

**Intern laptop (trapped on school WiFi):**
```bash
tunn relay 51820 --id=intern-wg --peer=home-wg
```
- Local WireGuard points to localhost:51820
- Traffic relays through tunn.to to `home-wg`

### WireGuard Config

**Intern's wg0.conf:**
```ini
[Interface]
PrivateKey = ...
Address = 10.0.0.2/24

[Peer]
PublicKey = <home-server-pubkey>
Endpoint = 127.0.0.1:51820  # tunn relay listens here
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

**Home server's wg0.conf:**
```ini
[Interface]
PrivateKey = ...
Address = 10.0.0.1/24
ListenPort = 51820  # tunn relay forwards here

[Peer]
PublicKey = <intern-pubkey>
AllowedIPs = 10.0.0.2/32
```

### Packet Flow

1. Intern's WireGuard sends UDP packet to `127.0.0.1:51820`
2. Local `tunn relay` captures packet, wraps in protobuf
3. Sends over gRPC stream to tunn.to
4. tunn.to looks up peer `home-wg`, forwards packet
5. Home's `tunn relay` receives, unwraps, sends UDP to `localhost:51820`
6. Home's WireGuard receives, processes, replies
7. Reply takes reverse path

## Protocol

Extend existing `UdpPacket` message:

```protobuf
message UdpPacket {
  string tunnel_id = 1;      // sender's tunnel ID
  string peer_id = 2;        // NEW: target peer tunnel ID (for relay mode)
  bytes data = 3;
  string source_addr = 4;    // original source (for reply routing)
}

message RelayConfig {
  string peer_id = 1;        // which tunnel to relay to
  bool bidirectional = 2;    // allow peer to send back (default true)
}
```

## Server-Side Relay Logic

```go
func (s *TunnelServer) handleUdpRelay(packet *pb.UdpPacket) {
    // Find target peer tunnel
    peerTunnel, exists := s.tunnels[packet.PeerId]
    if !exists {
        log.Warn("relay target not connected", "peer", packet.PeerId)
        return
    }

    // Verify peer relationship (both must declare each other)
    if !s.isPeerAuthorized(packet.TunnelId, packet.PeerId) {
        log.Warn("unauthorized relay attempt")
        return
    }

    // Forward packet to peer
    peerTunnel.Stream.Send(&pb.TunnelMessage{
        Message: &pb.TunnelMessage_UdpPacket{
            UdpPacket: &pb.UdpPacket{
                TunnelId:   packet.TunnelId,  // so peer knows who sent it
                Data:       packet.Data,
                SourceAddr: packet.SourceAddr,
            },
        },
    })
}
```

## Client-Side Relay

```go
func runRelay(localPort int, peerId string) {
    // Listen for local UDP (e.g., from WireGuard)
    conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: localPort})

    // gRPC stream to tunn.to
    stream := establishTunnel(tunnelId, &RelayConfig{PeerId: peerId})

    // Local → Remote
    go func() {
        buf := make([]byte, 65535)
        for {
            n, addr, _ := conn.ReadFromUDP(buf)
            stream.Send(&pb.UdpPacket{
                PeerId:     peerId,
                Data:       buf[:n],
                SourceAddr: addr.String(),
            })
        }
    }()

    // Remote → Local
    go func() {
        for {
            msg, _ := stream.Recv()
            if pkt := msg.GetUdpPacket(); pkt != nil {
                // Send to local app (parse SourceAddr for reply routing)
                conn.WriteToUDP(pkt.Data, parseAddr(pkt.SourceAddr))
            }
        }
    }()
}
```

## Security Considerations

1. **Mutual peering required:** Both tunnels must declare each other as peers. Prevents unauthorized relay.

2. **Pro tier only:** Relay uses bandwidth. Free tier gets normal tunneling, Pro gets relay.

3. **Rate limiting:** Same per-account bandwidth limits apply. Relay traffic counts against both peers.

4. **No packet inspection:** tunn sees encrypted WireGuard packets. Can't inspect contents.

5. **Abuse potential:** Could be used for bypassing network restrictions (that's... the point). Same as any VPN.

## CLI Design

```bash
# Basic relay (peer must also run relay pointing back)
tunn relay 51820 --peer=other-tunnel-id

# With custom tunnel ID
tunn relay 51820 --id=my-wg --peer=their-wg

# One-liner for WireGuard escape
tunn relay 51820 --peer=home-wg
```

## Why This Is Cool

1. **Escape hatch:** School/hotel/airport WiFi blocking UDP? No problem.

2. **No server setup:** Unlike running your own DERP, just `tunn relay` on both ends.

3. **Works with any UDP app:** WireGuard, game servers, DNS, whatever.

4. **Already have the pieces:** UDP tunneling exists, just need peer routing.

## Implementation Estimate

- Protocol changes: ~50 lines (add peer_id field)
- Server relay logic: ~100 lines
- Client relay mode: ~150 lines
- CLI flag parsing: ~30 lines
- Tests: ~200 lines

**Total: ~500 lines of Go**

## Not In Scope (For Now)

- **DERP protocol compatibility:** Could implement actual Tailscale DERP, but custom protocol is simpler and works.
- **STUN/direct connection:** Could try P2P first, fall back to relay. Adds complexity.
- **Multi-hop relay:** One relay server is enough. Multi-hop adds latency.

## Alternatives Considered

1. **Just use existing `tunn connect`:** Works for one-way, but relay needs bidirectional with peer addressing.

2. **Implement DERP protocol:** More work, ties us to Tailscale ecosystem. Custom is simpler.

3. **WebRTC data channels:** Overkill, we already have gRPC streams.
