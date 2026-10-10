package main

import (
	"reflect"
	"testing"
)

func TestMCPCommandShorthand(t *testing.T) {
	for _, tt := range []struct {
		args, command []string
		name          string
	}{
		{[]string{"npx", "-y", "server", "."}, []string{"npx", "-y", "server", "."}, ""},
		{[]string{"--name", "work", "--tools=echo", "docker", "mcp", "gateway", "run", "--profile", "work"}, []string{"docker", "mcp", "gateway", "run", "--profile", "work"}, "work"},
		{[]string{"--public", "./server"}, []string{"./server"}, ""},
		{[]string{"--name=work", "--", "./server", "--", "--name=child"}, []string{"./server", "--", "--name=child"}, "work"},
	} {
		opts, err := parseMCPFlags(normalizeMCPArgs(tt.args))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(opts.command, tt.command) || opts.tunnelID != tt.name {
			t.Fatalf("unexpected shorthand parse: %#v", opts)
		}
	}
	for _, args := range [][]string{{"--name", "http", "http://127.0.0.1:3000/mcp"}, {"--unknown", "server"}, {"--name"}, {"--"}} {
		if got := normalizeMCPArgs(args); !reflect.DeepEqual(got, args) {
			t.Fatalf("rewrote HTTP target or malformed flags: %v", got)
		}
	}
}
