// Package ippolicy validates and evaluates owner-configured network restrictions.
package ippolicy

import (
	"fmt"
	"net/netip"
	"strings"
)

const MaxCIDRs = 64

// Normalize accepts only CIDRs, masks host bits and removes duplicate networks.
// IPv4-mapped IPv6 prefixes must stay in the mapped /96 to avoid ambiguity.
func Normalize(values []string) ([]string, error) {
	if len(values) > MaxCIDRs {
		return nil, fmt.Errorf("at most %d CIDRs per list", MaxCIDRs)
	}
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if len(value) > 64 {
			return nil, fmt.Errorf("invalid CIDR")
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q; use an IPv4 or IPv6 network with a prefix length", value)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("mapped IPv4 CIDRs need a prefix length of at least 96")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		value = prefix.Masked().String()
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result, nil
}

// Allowed fails closed on malformed persisted rules. Deny always takes priority.
// With no rules an unknown peer does not change the relay's existing behavior.
func Allowed(peer string, allow, deny []string) bool {
	addr, err := netip.ParseAddr(peer)
	if err != nil {
		return len(allow) == 0 && len(deny) == 0
	}
	addr = addr.Unmap().WithZone("")
	match := len(allow) == 0
	for _, rules := range []struct {
		values []string
		deny   bool
	}{{allow, false}, {deny, true}} {
		if len(rules.values) > MaxCIDRs {
			return false
		}
		for _, value := range rules.values {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return false
			}
			if prefix.Contains(addr) {
				if rules.deny {
					return false
				}
				match = true
			}
		}
	}
	return match
}
