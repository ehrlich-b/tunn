package sshfront

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEdgeSSHCommandQuotingRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(20261010))
	alphabet := []rune("abcXYZ 09\t\n'\"\\$();+@é日本")
	for n := 0; n < 100; n++ {
		want := make([]string, 1+rng.Intn(5))
		quoted := make([]string, len(want))
		for i := range want {
			var value strings.Builder
			for count := rng.Intn(24); count > 0; count-- {
				value.WriteRune(alphabet[rng.Intn(len(alphabet))])
			}
			want[i] = value.String()
			quoted[i] = shellQuote(want[i])
		}
		got, err := SplitCommand(strings.Join(quoted, " "))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("seed=20261010 case=%d command=%q: got=%q want=%q error=%v", n, quoted, got, want, err)
		}
	}
	for _, command := range []string{`--name 'unfinished`, `--name "unfinished`, "--name tail\\"} {
		if _, err := SplitCommand(command); err == nil {
			t.Fatalf("accepted unterminated quoting: %q", command)
		}
	}
	got, err := SplitCommand(`--name "$USER" --target '$(id)' --allow alice@example.com;echo`)
	want := []string{"--name", "$USER", "--target", "$(id)", "--allow", "alice@example.com;echo"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("shell syntax was expanded: %q, %v", got, err)
	}
}

func TestEdgeSSHUsernameOptions(t *testing.T) {
	for _, tc := range []struct {
		user string
		want []string
		bad  bool
	}{
		{"tunn", nil, false}, {"ordinary-user", nil, false}, {"", nil, false},
		{"qr+inspect+bearer+allow+alice@example.com+allow-domain+example.com+name+demo+expire+2h", []string{"--qr", "--inspect", "--bearer", "--allow", "alice@example.com", "--allow-domain", "example.com", "--name", "demo", "--expire", "2h"}, false},
		{"public+name+demo", []string{"--public", "--name", "demo"}, false},
		{"allow", nil, true}, {"name", nil, true}, {"expire", nil, true},
		{"qr+unknown", nil, true}, {"qr+allow", nil, true},
	} {
		t.Run(tc.user, func(t *testing.T) {
			got, err := UsernameArgs(tc.user)
			if (err != nil) != tc.bad || err == nil && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("UsernameArgs=%q, %v; want=%q bad=%v", got, err, tc.want, tc.bad)
			}
		})
	}
}

func TestEdgeSSHOwnerCommandsDispatchArgumentsLiterally(t *testing.T) {
	for _, args := range [][]string{
		{"keys", "add", "ssh-ed25519 fixture comment"},
		{"login", "--email", "owner+alias@example.com"},
		{"hosts", "--json"}, {"usage", "demo", "--since", "24h"},
		{"grant", "create", "demo", "--for", "alice@example.com"},
		{"service", "check", "--config", "-"},
		{"openclaw", "--name", "home-openclaw"}, {"connect", "database"},
		{"magic-link", "--email", "owner@example.com"},
	} {
		t.Run(args[0], func(t *testing.T) {
			var called atomic.Bool
			client := startupClient(t, Config{Command: func(ctx context.Context, id Identity, got []string, in io.Reader, out io.Writer) error {
				called.Store(true)
				if !reflect.DeepEqual(got, args) || id.Fingerprint == "" {
					return fmt.Errorf("dispatch changed arguments or identity: %q %+v", got, id)
				}
				returnValue, err := io.ReadAll(in)
				if err != nil || string(returnValue) != "version: 1\n" {
					return fmt.Errorf("stdin=%q error=%v", returnValue, err)
				}
				_, err = io.WriteString(out, "command complete\n")
				return err
			}})
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			session.Stdin = strings.NewReader("version: 1\n")
			quoted := make([]string, len(args))
			for i, arg := range args {
				quoted[i] = shellQuote(arg)
			}
			output, err := session.CombinedOutput("-- " + strings.Join(quoted, " "))
			if err != nil || string(output) != "command complete\n" || !called.Load() {
				t.Fatalf("dispatch output=%q called=%v error=%v", output, called.Load(), err)
			}
		})
	}
}
