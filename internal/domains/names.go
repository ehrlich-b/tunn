package domains

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeName accepts concrete ASCII DNS names only. No wildcard, IP, URL,
// port, or control-origin alias can enter the customer namespace.
func NormalizeName(name, base string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	base = strings.TrimSuffix(strings.ToLower(base), ".")
	if len(name) > 253 || !strings.Contains(name, ".") || net.ParseIP(name) != nil || name == base || strings.HasSuffix(name, "."+base) {
		return "", fmt.Errorf("require a customer DNS name outside the relay domain")
	}
	for _, label := range strings.Split(name, ".") {
		if !ValidLabel(label) {
			return "", fmt.Errorf("invalid DNS name")
		}
	}
	// All-numeric suffixes are not registrable DNS names.
	suffix := name[strings.LastIndex(name, ".")+1:]
	hasLetter := false
	for _, c := range suffix {
		if c >= 'a' && c <= 'z' {
			hasLetter = true
		}
	}
	if !hasLetter {
		return "", fmt.Errorf("invalid DNS suffix")
	}
	return name, nil
}
func ValidLabel(name string) bool {
	if len(name) == 0 || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for _, c := range name {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
