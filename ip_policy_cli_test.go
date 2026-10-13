package main

import (
	"testing"
)

func TestIPPolicyCLIParsing(t *testing.T) {
	for _, args := range [][]string{
		{"get", "app"}, {"clear", "app"}, {"set", "--account", "--allow", "192.0.2.9/24,2001:db8::/32"},
		{"set", "app", "--deny", "::ffff:192.0.2.1/128"}, {"set", "--deny", "192.0.2.1/32", "app"},
		{"set", "app", "--allow", "", "--deny", ""},
		{"get", "--account", "--owner-token-file", "owner.jwt"},
	} {
		if _, err := parseIPPolicy(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{}, {"set"}, {"get", "app", "--deny", ""}, {"get", "app", "--allow", "192.0.2.0/24"},
		{"set", "app", "--account"}, {"clear", "bad/name"}, {"set", "app", "--allow", "192.0.2.1"},
		{"set", "app", "--deny", "2001:db8::/129"}, {"set", "app", "another"}, {"bogus", "app"},
		{"set", "app", "--allow", "192.0.2.0/24,"},
	} {
		if _, err := parseIPPolicy(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	o, err := parseIPPolicy([]string{"set", "app", "--allow", "192.0.2.99/24"})
	if err != nil || o.allow[0] != "192.0.2.0/24" {
		t.Fatal(o, err)
	}
}
