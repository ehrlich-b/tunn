package main

import "strings"

// Preserve explicit delimiters and HTTP targets while allowing the short form
// `tunn mcp command args...`. Flags after the command belong to the child.
func normalizeMCPArgs(args []string) []string {
	valueFlags := map[string]bool{"name": true, "id": true, "subdomain": true, "allow": true, "tunnel-key": true, "secret": true, "tools": true}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			return args
		}
		if strings.HasPrefix(arg, "-") {
			name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
			if valueFlags[name] {
				if !hasValue {
					index++
				}
				continue
			}
			if name == "public" {
				continue
			}
			return args // let the flag parser report unknown options
		}
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			return args
		}
		out := append([]string(nil), args[:index]...)
		out = append(out, "--")
		return append(out, args[index:]...)
	}
	return args
}
