package cliopts

import (
	"reflect"
	"testing"
	"time"
)

func TestEdgeSSHAllServeFlagsMatchCLI(t *testing.T) {
	for _, alias := range []string{"name", "id", "subdomain"} {
		flags := []string{"--" + alias + "=demo", "--target=https://localhost:8443", "--allow=alice@example.com", "--allow=bob@example.com",
			"--allow-domain=EXAMPLE.COM", "--skip-local-tls-verify", "--inspect", "--inspect-body", "--bearer", "--require-upstream-auth",
			"--qr", "--expire=2h", "--ws-idle-timeout=15s", "--ws-keepalive=5s", "--ws-max-message-size=12345"}
		local, err := ParseServe(flags, true)
		if err != nil {
			t.Fatal(err)
		}
		remote, err := ParseSSHPublication(flags, "serve")
		if err != nil || !reflect.DeepEqual(local, remote) {
			t.Fatalf("SSH flag drift for %s: local=%+v remote=%+v error=%v", alias, local, remote, err)
		}
		if remote.Name != "demo" || remote.WebSocket.IdleTimeout != 15*time.Second || remote.WebSocket.KeepaliveInterval != 5*time.Second || remote.WebSocket.MaxMessageSize != 12345 {
			t.Fatalf("alias/WS flags lost: %+v", remote)
		}
	}
	for _, flags := range [][]string{{"--ws-idle-timeout=-1s"}, {"--ws-keepalive=-1s"}, {"--ws-max-message-size=104857601"}, {"--ws-max-message-size=not-a-number"}} {
		if _, err := ParseSSHPublication(flags, "serve"); err == nil {
			t.Fatalf("invalid WebSocket option accepted: %q", flags)
		}
	}
}
