package common

import (
	"regexp"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	for _, tt := range []struct {
		name, input, want string
	}{
		{"whitespace and case", "  Alice@EXAMPLE.COM\t", "alice@example.com"},
		{"compatibility letters", "Ａｌｉｃｅ@example.com", "alice@example.com"},
		{"canonical composition", "e\u0301@example.com", "é@example.com"},
		{"Cyrillic stays distinct", "аlice@example.com", "аlice@example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeEmail(tt.input); got != tt.want {
				t.Errorf("NormalizeEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRandID(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"zero length", 0},
		{"length 1", 1},
		{"length 5", 5},
		{"length 10", 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RandID(tt.length)

			if len(result) != tt.length {
				t.Errorf("got length %d, want %d", len(result), tt.length)
			}

			if tt.length > 0 {
				validChars := regexp.MustCompile("^[a-z0-9]+$")
				if !validChars.MatchString(result) {
					t.Errorf("invalid characters in: %s", result)
				}
			}
		})
	}
}

func TestRandIDUniqueness(t *testing.T) {
	results := make(map[string]bool)

	for i := 0; i < 100; i++ {
		id := RandID(10)
		if results[id] {
			t.Errorf("duplicate ID: %s", id)
		}
		results[id] = true
	}
}

func TestRandIDLarge(t *testing.T) {
	result := RandID(1000)
	if len(result) != 1000 {
		t.Errorf("got length %d, want 1000", len(result))
	}
}
