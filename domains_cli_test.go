package main

import (
	"errors"
	"flag"
	"testing"
)

func TestParseDomainOptions(t *testing.T) {
	for _, args := range [][]string{
		{"add", "Work.Example.com.", "--tunnel", "site", "--server=https://relay.test", "--owner-token-file", "owner"},
		{"verify", "--server", "relay.test", "work.example.com"},
		{"list", "--insecure"}, {"delete", "work.example.com"},
	} {
		o, err := parseDomainOptions(args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if o.action != "list" && o.name != "work.example.com" {
			t.Fatal(o)
		}
	}
	for _, args := range [][]string{{}, {"unknown"}, {"add", "work.example.com"}, {"add", "https://work.example.com", "--tunnel", "site"}, {"list", "work.example.com"}, {"delete", "../secret"}, {"verify", "work.example.com", "--server"}, {"add", "work.example.com", "--tunnel", "-site"}, {"verify", "work.example.com", "--tunnel", "site"}} {
		if _, err := parseDomainOptions(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if _, err := parseDomainOptions([]string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
}

func TestParseWildcardDomainOptions(t *testing.T) {
	for _, args := range [][]string{{"add", "*.apps.ehrlich.dev"}, {"add", "*.apps.ehrlich.dev", "--tunnel", "dashboard"}, {"verify", "*.apps.ehrlich.dev"}, {"delete", "*.apps.ehrlich.dev"}} {
		if _, err := parseDomainOptions(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
}
