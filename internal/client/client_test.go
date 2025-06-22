package client

import (
	"strings"
	"testing"
)

func TestNormalizeTargetURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		hasError bool
	}{
		{"port only", "8000", "http://localhost:8000", false},
		{"port only leading zero", "08000", "http://localhost:08000", false},
		{"host and port", "localhost:8000", "http://localhost:8000", false},
		{"host and port different host", "example.com:3000", "http://example.com:3000", false},
		{"full http URL", "http://localhost:8000", "http://localhost:8000", false},
		{"full https URL", "https://example.com:443", "https://example.com:443", false},
		{"empty string", "", "", true},
		{"invalid characters", "abc123", "", true},
		{"mixed invalid", "8000abc", "", true},
		{"invalid URL", "http://[invalid", "", true},
	}

	client := &Client{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.NormalizeTargetURL(tt.input)
			
			if tt.hasError {
				if err == nil {
					t.Errorf("expected error for input %q", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for input %q: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("input %q: got %q, want %q", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestClientValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		client      Client
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config full URL",
			client: Client{
				ID:     "test123",
				To:     "http://localhost:8000",
				Domain: "tunn.to",
				Token:  "test-token",
			},
			expectError: false,
		},
		{
			name: "valid config port only",
			client: Client{
				ID:     "test123",
				To:     "8000",
				Domain: "tunn.to",
				Token:  "test-token",
			},
			expectError: false,
		},
		{
			name: "valid config host:port",
			client: Client{
				ID:     "test123",
				To:     "localhost:8000",
				Domain: "tunn.to",
				Token:  "test-token",
			},
			expectError: false,
		},
		{
			name: "missing token",
			client: Client{
				ID:     "test123",
				To:     "http://localhost:8000",
				Domain: "tunn.to",
				Token:  "",
			},
			expectError: true,
			errorMsg:    "token is required",
		},
		{
			name: "missing domain",
			client: Client{
				ID:     "test123",
				To:     "http://localhost:8000",
				Domain: "",
				Token:  "test-token",
			},
			expectError: true,
			errorMsg:    "domain is required",
		},
		{
			name: "missing target URL",
			client: Client{
				ID:     "test123",
				To:     "",
				Domain: "tunn.to",
				Token:  "test-token",
			},
			expectError: true,
			errorMsg:    "target URL is required",
		},
		{
			name: "invalid target URL",
			client: Client{
				ID:     "test123",
				To:     "abc123",
				Domain: "tunn.to",
				Token:  "test-token",
			},
			expectError: true,
			errorMsg:    "invalid target URL",
		},
		{
			name: "valid config without ID",
			client: Client{
				ID:     "",
				To:     "https://example.com:8080",
				Domain: "tunn.to",
				Token:  "test-token",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy to avoid modifying the test case
			client := tt.client
			err := client.ValidateConfig()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				// For valid configs, check that URL was normalized to full format
				if !strings.HasPrefix(client.To, "http://") && !strings.HasPrefix(client.To, "https://") {
					t.Errorf("Expected URL to be normalized to full format, got: %s", client.To)
				}
			}
		})
	}
}

func TestClientGetPublicURL(t *testing.T) {
	tests := []struct {
		name     string
		client   Client
		expected string
	}{
		{
			name: "with ID",
			client: Client{
				ID:     "abc123",
				Domain: "tunn.to",
			},
			expected: "https://abc123.tunn.to",
		},
		{
			name: "without ID",
			client: Client{
				ID:     "",
				Domain: "tunn.to",
			},
			expected: "",
		},
		{
			name: "with custom domain",
			client: Client{
				ID:     "test-tunnel",
				Domain: "example.com",
			},
			expected: "https://test-tunnel.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.client.GetPublicURL()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestClientGenerateIDIfEmpty(t *testing.T) {
	t.Run("generates ID when empty", func(t *testing.T) {
		client := &Client{ID: ""}
		client.GenerateIDIfEmpty()

		if client.ID == "" {
			t.Error("ID should have been generated")
		}

		if len(client.ID) != 7 {
			t.Errorf("Expected ID length 7, got %d", len(client.ID))
		}

		// Check that it only contains valid characters
		for _, char := range client.ID {
			if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')) {
				t.Errorf("ID contains invalid character: %c", char)
			}
		}
	})

	t.Run("preserves existing ID", func(t *testing.T) {
		originalID := "existing-id"
		client := &Client{ID: originalID}
		client.GenerateIDIfEmpty()

		if client.ID != originalID {
			t.Errorf("Expected ID to remain %s, got %s", originalID, client.ID)
		}
	})

	t.Run("generates unique IDs", func(t *testing.T) {
		ids := make(map[string]bool)
		
		for i := 0; i < 100; i++ {
			client := &Client{ID: ""}
			client.GenerateIDIfEmpty()
			
			if ids[client.ID] {
				t.Errorf("Generated duplicate ID: %s", client.ID)
			}
			ids[client.ID] = true
		}
	})
}

func TestClientConfiguration(t *testing.T) {
	t.Run("complete valid configuration", func(t *testing.T) {
		client := &Client{
			ID:     "",
			To:     "http://localhost:3000",
			Domain: "tunn.to",
			Token:  "secret-token",
		}

		// Test ID generation
		client.GenerateIDIfEmpty()
		if client.ID == "" {
			t.Error("ID should have been generated")
		}

		// Test validation
		if err := client.ValidateConfig(); err != nil {
			t.Errorf("Valid config should not return error: %v", err)
		}

		// Test public URL generation
		expectedURL := "https://" + client.ID + ".tunn.to"
		if publicURL := client.GetPublicURL(); publicURL != expectedURL {
			t.Errorf("Expected public URL %s, got %s", expectedURL, publicURL)
		}
	})
}

