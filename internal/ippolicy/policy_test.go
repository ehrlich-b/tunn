package ippolicy

import (
	"reflect"
	"strings"
	"testing"
)

func TestIPPolicyNormalize(t *testing.T) {
	got, err := Normalize([]string{" 192.0.2.99/24 ", "192.0.2.0/24", "2001:db8::abcd/48", "::ffff:198.51.100.9/120"})
	want := []string{"192.0.2.0/24", "2001:db8::/48", "198.51.100.0/24"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v %v", got, err)
	}
	for _, value := range []string{"192.0.2.1", "example.com/24", "192.0.2.0/33", "2001:db8::/129", "::ffff:0:0/80", "fe80::1%eth0/64", "", strings.Repeat("x", 65)} {
		if _, err := Normalize([]string{value}); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	if _, err := Normalize(make([]string, MaxCIDRs+1)); err == nil {
		t.Fatal("accepted oversized list")
	}
	if _, err := Normalize(nil); err != nil {
		t.Fatal(err)
	}
}
func TestIPPolicyAllowed(t *testing.T) {
	for _, tt := range []struct {
		peer        string
		allow, deny []string
		want        bool
	}{
		{"192.0.2.10", nil, nil, true},
		{"192.0.2.10", []string{"192.0.2.0/24"}, nil, true},
		{"198.51.100.10", []string{"192.0.2.0/24"}, nil, false},
		{"192.0.2.10", []string{"192.0.2.0/24"}, []string{"192.0.2.10/32"}, false},
		{"192.0.2.10", nil, []string{"198.51.100.0/24"}, true},
		{"192.0.2.10", nil, []string{"0.0.0.0/0"}, false},
		{"2001:db8::10", []string{"2001:db8::/32"}, nil, true},
		{"2001:db9::10", []string{"2001:db8::/32"}, nil, false},
		{"2001:db8::10", []string{"::/0"}, []string{"2001:db8::10/128"}, false},
		{"::ffff:192.0.2.10", []string{"192.0.2.0/24"}, nil, true},
		{"2001:db8::10", []string{"0.0.0.0/0"}, nil, false},
		{"fe80::10%eth0", []string{"fe80::/10"}, nil, true},
		{"fe80::10%eth0", nil, []string{"fe80::/10"}, false},
		{"unknown-peer", nil, nil, true},
		{"unknown-peer", nil, []string{"192.0.2.0/24"}, false},
		{"192.0.2.10", nil, []string{"broken"}, false},
		{"192.0.2.10", []string{"broken"}, nil, false},
	} {
		if got := Allowed(tt.peer, tt.allow, tt.deny); got != tt.want {
			t.Errorf("peer=%s allow=%v deny=%v got=%v", tt.peer, tt.allow, tt.deny, got)
		}
	}
}
