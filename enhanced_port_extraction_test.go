package main

import (
	"testing"
)

// TestExtractPortFromHostWithDomainMatcher tests enhanced port extraction with domain matcher
func TestExtractPortFromHostWithDomainMatcher(t *testing.T) {
	// Create a test domain matcher
	logger := NewStructuredLogger(nil)
	domainMatcher := NewPatternMatcher(logger)

	// Add test patterns
	err := domainMatcher.AddPattern("*.sankalpmukim.dev")
	if err != nil {
		t.Fatalf("Failed to add domain pattern: %v", err)
	}

	err = domainMatcher.AddPattern("*.example.com")
	if err != nil {
		t.Fatalf("Failed to add domain pattern: %v", err)
	}

	tests := []struct {
		name          string
		host          string
		expectedPort  int
		expectedOk    bool
		expectedError string
	}{
		{
			name:         "valid subdomain with port - sankalpmukim.dev",
			host:         "3000.sankalpmukim.dev",
			expectedPort: 3000,
			expectedOk:   true,
		},
		{
			name:         "valid subdomain with port - example.com",
			host:         "8080.example.com",
			expectedPort: 8080,
			expectedOk:   true,
		},
		{
			name:         "valid large port number",
			host:         "65535.sankalpmukim.dev",
			expectedPort: 65535,
			expectedOk:   true,
		},
		{
			name:         "valid small port number",
			host:         "1.sankalpmukim.dev",
			expectedPort: 1,
			expectedOk:   true,
		},
		{
			name:          "empty host",
			host:          "",
			expectedOk:    false,
			expectedError: "host header cannot be empty",
		},
		{
			name:          "host not matching patterns",
			host:          "3000.invalid.com",
			expectedOk:    false,
			expectedError: "does not match any configured domain patterns",
		},
		{
			name:          "invalid port format",
			host:          "abc.sankalpmukim.dev",
			expectedOk:    false,
			expectedError: "does not match any configured domain patterns",
		},
		{
			name:          "port out of range - zero",
			host:          "0.sankalpmukim.dev",
			expectedOk:    false,
			expectedError: "port 0 is out of valid range",
		},
		{
			name:          "port out of range - too large",
			host:          "65536.sankalpmukim.dev",
			expectedOk:    false,
			expectedError: "port 65536 is out of valid range",
		},
		{
			name:         "host with port suffix",
			host:         "3000.sankalpmukim.dev:8080",
			expectedPort: 3000,
			expectedOk:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, ok, err := extractPortFromHostWithDomainMatcher(tt.host, domainMatcher)

			if ok != tt.expectedOk {
				t.Errorf("Expected ok=%v, got ok=%v", tt.expectedOk, ok)
			}

			if tt.expectedOk {
				if port != tt.expectedPort {
					t.Errorf("Expected port=%d, got port=%d", tt.expectedPort, port)
				}
				if err != nil {
					t.Errorf("Expected no error, got error=%v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error containing '%s', got no error", tt.expectedError)
				} else if tt.expectedError != "" && !containsString(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got error='%s'", tt.expectedError, err.Error())
				}
			}
		})
	}
}

// TestValidatePortInConfiguredList tests port validation against configured lists
func TestValidatePortInConfiguredList(t *testing.T) {
	configuredPorts := []int{3000, 8080, 5173, 9000}

	tests := []struct {
		name     string
		port     int
		expected bool
	}{
		{
			name:     "port in configured list - 3000",
			port:     3000,
			expected: true,
		},
		{
			name:     "port in configured list - 8080",
			port:     8080,
			expected: true,
		},
		{
			name:     "port in configured list - 5173",
			port:     5173,
			expected: true,
		},
		{
			name:     "port in configured list - 9000",
			port:     9000,
			expected: true,
		},
		{
			name:     "port not in configured list - 4000",
			port:     4000,
			expected: false,
		},
		{
			name:     "port not in configured list - 80",
			port:     80,
			expected: false,
		},
		{
			name:     "port not in configured list - 443",
			port:     443,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validatePortInConfiguredList(tt.port, configuredPorts)
			if result != tt.expected {
				t.Errorf("validatePortInConfiguredList(%d) = %v, expected %v", tt.port, result, tt.expected)
			}
		})
	}
}

// TestExtractAndValidatePort tests comprehensive port extraction and validation
func TestExtractAndValidatePort(t *testing.T) {
	configuredPorts := []int{3000, 8080, 5173}

	// Create domain matcher for web service mode tests
	logger := NewStructuredLogger(nil)
	domainMatcher := NewPatternMatcher(logger)
	err := domainMatcher.AddPattern("*.sankalpmukim.dev")
	if err != nil {
		t.Fatalf("Failed to add domain pattern: %v", err)
	}

	tests := []struct {
		name          string
		host          string
		mode          DeploymentMode
		expectedPort  int
		expectedError string
	}{
		// Local mode tests
		{
			name:         "local mode - valid port",
			host:         "3000.local",
			mode:         LocalMode,
			expectedPort: 3000,
		},
		{
			name:         "local mode - valid dev domain",
			host:         "8080.dev",
			mode:         LocalMode,
			expectedPort: 8080,
		},
		{
			name:          "local mode - invalid format",
			host:          "invalid.local",
			mode:          LocalMode,
			expectedError: "invalid host format",
		},
		{
			name:          "local mode - port not configured",
			host:          "4000.local",
			mode:          LocalMode,
			expectedError: "port 4000 not configured",
		},
		{
			name:          "local mode - port out of range",
			host:          "0.local",
			mode:          LocalMode,
			expectedError: "port 0 is out of valid range",
		},

		// Web service mode tests
		{
			name:         "web service mode - valid port",
			host:         "3000.sankalpmukim.dev",
			mode:         WebServiceMode,
			expectedPort: 3000,
		},
		{
			name:         "web service mode - valid port 8080",
			host:         "8080.sankalpmukim.dev",
			mode:         WebServiceMode,
			expectedPort: 8080,
		},
		{
			name:          "web service mode - domain not matching",
			host:          "3000.invalid.com",
			mode:          WebServiceMode,
			expectedError: "does not match any configured domain patterns",
		},
		{
			name:          "web service mode - port not configured",
			host:          "4000.sankalpmukim.dev",
			mode:          WebServiceMode,
			expectedError: "port 4000 not configured",
		},
		{
			name:          "web service mode - port out of range",
			host:          "65536.sankalpmukim.dev",
			mode:          WebServiceMode,
			expectedError: "port 65536 is out of valid range",
		},
		{
			name:          "web service mode - empty host",
			host:          "",
			mode:          WebServiceMode,
			expectedError: "host header cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matcher DomainMatcher
			if tt.mode == WebServiceMode {
				matcher = domainMatcher
			}

			port, err := extractAndValidatePort(tt.host, configuredPorts, matcher, tt.mode)

			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("Expected error containing '%s', got no error", tt.expectedError)
				} else if !containsString(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got error='%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got error=%v", err)
				}
				if port != tt.expectedPort {
					t.Errorf("Expected port=%d, got port=%d", tt.expectedPort, port)
				}
			}
		})
	}
}

// TestExtractAndValidatePortEdgeCases tests edge cases for port extraction and validation
func TestExtractAndValidatePortEdgeCases(t *testing.T) {
	configuredPorts := []int{3000, 8080}

	tests := []struct {
		name            string
		host            string
		configuredPorts []int
		matcher         DomainMatcher
		mode            DeploymentMode
		expectedError   string
	}{
		{
			name:            "web service mode - nil domain matcher",
			host:            "3000.sankalpmukim.dev",
			configuredPorts: configuredPorts,
			matcher:         nil,
			mode:            WebServiceMode,
			expectedError:   "domain matcher not configured for web service mode",
		},
		{
			name:            "unsupported deployment mode",
			host:            "3000.local",
			configuredPorts: configuredPorts,
			matcher:         nil,
			mode:            DeploymentMode(999), // Invalid mode
			expectedError:   "unsupported deployment mode",
		},
		{
			name:            "empty configured ports list",
			host:            "3000.local",
			configuredPorts: []int{},
			matcher:         nil,
			mode:            LocalMode,
			expectedError:   "port 3000 not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extractAndValidatePort(tt.host, tt.configuredPorts, tt.matcher, tt.mode)

			if err == nil {
				t.Errorf("Expected error containing '%s', got no error", tt.expectedError)
			} else if !containsString(err.Error(), tt.expectedError) {
				t.Errorf("Expected error containing '%s', got error='%s'", tt.expectedError, err.Error())
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(substr) > 0 && len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				findSubstring(s, substr))))
}

// Helper function to find substring in string
func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
