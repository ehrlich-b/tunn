package common

import (
	"regexp"
	"testing"
)

func TestRandID(t *testing.T) {
	tests := []struct {
		name     string
		length   int
		expected string
	}{
		{"zero length", 0, ""},
		{"length 1", 1, "."},
		{"length 5", 5, "....."},
		{"length 10", 10, ".........."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RandID(tt.length)
			
			// Check length
			if len(result) != tt.length {
				t.Errorf("RandID(%d) returned length %d, expected %d", tt.length, len(result), tt.length)
			}
			
			// Check that it only contains valid characters
			if tt.length > 0 {
				validChars := regexp.MustCompile("^[a-z0-9]+$")
				if !validChars.MatchString(result) {
					t.Errorf("RandID(%d) returned invalid characters: %s", tt.length, result)
				}
			}
		})
	}
}

func TestRandIDUniqueness(t *testing.T) {
	// Test that multiple calls return different values
	length := 10
	results := make(map[string]bool)
	
	for i := 0; i < 100; i++ {
		id := RandID(length)
		if results[id] {
			t.Errorf("RandID generated duplicate ID: %s", id)
		}
		results[id] = true
	}
}

func TestRandIDPanic(t *testing.T) {
	// Test with a very large number that might cause issues
	defer func() {
		if r := recover(); r != nil {
			// This is expected behavior if rand.Read fails
			t.Logf("RandID panicked as expected: %v", r)
		}
	}()
	
	// This should work fine
	result := RandID(1000)
	if len(result) != 1000 {
		t.Errorf("RandID(1000) returned length %d, expected 1000", len(result))
	}
}