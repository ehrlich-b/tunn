package cliopts

import (
	"reflect"
	"testing"
	"time"
)

func TestServeSharedFlags(t *testing.T) {
	flags := []string{"--allow", "bob@x.com,alice@y.com", "--allow-domain", "example.com", "--expire", "2h", "--name", "demo", "--qr", "--bearer", "--inspect", "--require-upstream-auth", "--ws-idle-timeout=0"}
	cli, err := ParseServe(append([]string{"8080"}, flags...), true)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := ParseServe(flags, false)
	if err != nil {
		t.Fatal(err)
	}
	cli.Target = ""
	if !reflect.DeepEqual(cli, remote) {
		t.Fatalf("CLI/SSH drift: %#v != %#v", cli, remote)
	}
	if remote.Expire != 2*time.Hour || remote.Name != "demo" || !remote.QR || len(remote.AllowedEmails) != 3 {
		t.Fatalf("options=%#v", remote)
	}
	for _, flags := range [][]string{{"--public", "--allow", "a@example.com"}, {"--public", "--allow-domain", "example.com"}, {"--expire=-1s"}, {"--allow-domain=bad"}, {"--name"}, {"--ws-max-message-size=0"}} {
		if _, err := ParseServe(flags, false); err == nil {
			t.Fatalf("accepted %v", flags)
		}
	}
}
