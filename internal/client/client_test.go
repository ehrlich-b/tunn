package client

import (
	"testing"
)

func TestClientValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		client      Client
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			client: Client{
				ID:     "test123",
				To:     "http://localhost:8000",
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
				To:     "\n\t\x00://invalid",
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
			err := tt.client.ValidateConfig()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !containsString(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
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

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}