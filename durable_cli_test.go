package main

import "testing"

func TestDurableForgeFlags(t *testing.T) {
	publisher, err := parseTCPFlags([]string{"--account-only", "--name", "forge-ssh", "127.0.0.1:22"})
	if err != nil || !publisher.accountOnly || publisher.tunnelID != "forge-ssh" {
		t.Fatal(publisher, err)
	}
	connector, err := parseConnectFlags([]string{"--stdio", "--account", "forge-ssh"})
	if err != nil || !connector.account || !connector.stdio {
		t.Fatal(connector, err)
	}
	for _, args := range [][]string{{"--account", "--public", "forge-ssh"}, {"--account", "--token", "secret", "forge-ssh"}, {"--stdio", "--listen", "127.0.0.1:0", "forge-ssh"}} {
		if _, err := parseConnectFlags(args); err == nil {
			t.Fatal("conflicting connect flags accepted", args)
		}
	}
	if _, err := parseTCPFlags([]string{"--account-only", "--public", "127.0.0.1:22"}); err == nil {
		t.Fatal("public account-only accepted")
	}
}
