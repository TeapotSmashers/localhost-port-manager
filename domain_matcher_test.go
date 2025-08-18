package main

import (
	"fmt"
	"io"
	"log"
	"testing"
)

// TestNewPatternMatcher tests PatternMatcher creation
func TestNewPatternMatcher(t *testing.T) {
	logger := NewStructuredLogger(log.New(io.Discard, "", 0))

	pm := NewPatternMatcher(logger)
	if pm == nil {
		t.Fatal("NewPatternMatcher returned nil")
	}

	if len(pm.patterns) != 0 {
		t.Errorf("Expected empty patterns, got %d patterns", len(pm.patterns))
	}

	if len(pm.compiledRegexs) != 0 {
		t.Errorf("Expected empty compiled regexes, got %d regexes", len(pm.compiledRegexs))
	}
}

// TestPatternMatcher_AddPattern tests adding domain patterns
func TestPatternMatcher_AddPattern(t *testing.T) {
	logger := NewStructuredLogger(log.New(io.Discard, "", 0))
	pm := NewPatternMatcher(logger)

	tests := []struct {
		name        string
		pattern     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid wildcard pattern",
			pattern:     "*.sankalpmukim.dev",
			expectError: false,
		},
		{
			name:        "valid wildcard pattern with multiple subdomains",
			pattern:     "*.api.example.com",
			expectError: false,
		},
		{
			name:        "valid exact pattern",
			pattern:     "app.example.com",
			expectError: false,
		},
		{
			name:        "empty pattern",
			pattern:     "",
			expectError: true,
			errorMsg:    "domain pattern cannot be empty",
		},
		{
			name:        "invalid pattern - no dot",
			pattern:     "localhost",
			expectError: true,
			errorMsg:    "domain pattern must contain at least one dot",
		},
		{
			name:        "invalid pattern - wildcard in middle",
			pattern:     "app.*.example.com",
			expectError: true,
			errorMsg:    "wildcard (*) can only be used at the beginning of the pattern",
		},
		{
			name:        "invalid pattern - multiple wildcards",
			pattern:     "*.*.example.com",
			expectError: true,
			errorMsg:    "wildcard (*) can only be used at the beginning of the pattern",
		},
		{
			name:        "invalid pattern - invalid characters",
			pattern:     "*.example$.com",
			expectError: true,
			errorMsg:    "domain pattern contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pm.AddPattern(tt.pattern)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for pattern '%s', but got none", tt.pattern)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for pattern '%s': %v", tt.pattern, err)
				}
			}
		})
	}
}

// TestPatternMatcher_MatchesPattern tests domain pattern matching
func TestPatternMatcher_MatchesPattern(t *testing.T) {
	logger := NewStructuredLogger(log.New(io.Discard, "", 0))
	pm := NewPatternMatcher(logger)

	// Add test patterns
	patterns := []string{
		"*.sankalpmukim.dev",
		"*.example.com",
		"app.test.local",
	}

	for _, pattern := range patterns {
		if err := pm.AddPattern(pattern); err != nil {
			t.Fatalf("Failed to add pattern '%s': %v", pattern, err)
		}
	}

	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "matches wildcard pattern - sankalpmukim.dev",
			host:     "3000.sankalpmukim.dev",
			expected: true,
		},
		{
			name:     "matches wildcard pattern - example.com",
			host:     "8080.example.com",
			expected: true,
		},
		{
			name:     "matches exact pattern",
			host:     "app.test.local",
			expected: true,
		},
		{
			name:     "matches with port suffix",
			host:     "3000.sankalpmukim.dev:8080",
			expected: true,
		},
		{
			name:     "does not match different domain",
			host:     "3000.different.com",
			expected: false,
		},
		{
			name:     "does not match subdomain of exact pattern",
			host:     "sub.app.test.local",
			expected: false,
		},
		{
			name:     "empty host",
			host:     "",
			expected: false,
		},
		{
			name:     "invalid host format",
			host:     "invalid-host",
			expected: false,
		},
		{
			name:     "matches complex port number",
			host:     "65535.sankalpmukim.dev",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.MatchesPattern(tt.host)
			if result != tt.expected {
				t.Errorf("MatchesPattern(%s) = %v, expected %v", tt.host, result, tt.expected)
			}
		})
	}
}

// TestPatternMatcher_ExtractPort tests port extraction from subdomain format
func TestPatternMatcher_ExtractPort(t *testing.T) {
	logger := NewStructuredLogger(log.New(io.Discard, "", 0))
	pm := NewPatternMatcher(logger)

	// Add test patterns
	patterns := []string{
		"*.sankalpmukim.dev",
		"*.example.com",
		"*.test.local",
	}

	for _, pattern := range patterns {
		if err := pm.AddPattern(pattern); err != nil {
			t.Fatalf("Failed to add pattern '%s': %v", pattern, err)
		}
	}

	tests := []struct {
		name         string
		host         string
		expectedPort int
		expectedOk   bool
	}{
		{
			name:         "extract port from sankalpmukim.dev",
			host:         "3000.sankalpmukim.dev",
			expectedPort: 3000,
			expectedOk:   true,
		},
		{
			name:         "extract port from example.com",
			host:         "8080.example.com",
			expectedPort: 8080,
			expectedOk:   true,
		},
		{
			name:         "extract port with port suffix",
			host:         "5173.test.local:9000",
			expectedPort: 5173,
			expectedOk:   true,
		},
		{
			name:         "extract large port number",
			host:         "65535.sankalpmukim.dev",
			expectedPort: 65535,
			expectedOk:   true,
		},
		{
			name:         "extract single digit port",
			host:         "1.example.com",
			expectedPort: 1,
			expectedOk:   true,
		},
		{
			name:         "no match - different domain",
			host:         "3000.different.com",
			expectedPort: 0,
			expectedOk:   false,
		},
		{
			name:         "no match - invalid format",
			host:         "invalid.sankalpmukim.dev",
			expectedPort: 0,
			expectedOk:   false,
		},
		{
			name:         "no match - empty host",
			host:         "",
			expectedPort: 0,
			expectedOk:   false,
		},
		{
			name:         "no match - no port in subdomain",
			host:         "app.sankalpmukim.dev",
			expectedPort: 0,
			expectedOk:   false,
		},
		{
			name:         "no match - leading zeros",
			host:         "0003000.sankalpmukim.dev",
			expectedPort: 3000,
			expectedOk:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, ok := pm.ExtractPort(tt.host)

			if ok != tt.expectedOk {
				t.Errorf("ExtractPort(%s) ok = %v, expected %v", tt.host, ok, tt.expectedOk)
			}

			if port != tt.expectedPort {
				t.Errorf("ExtractPort(%s) port = %d, expected %d", tt.host, port, tt.expectedPort)
			}
		})
	}
}

// TestPatternMatcher_ValidatePatterns tests pattern validation
func TestPatternMatcher_ValidatePatterns(t *testing.T) {
	logger := NewStructuredLogger(log.New(io.Discard, "", 0))

	t.Run("no patterns configured", func(t *testing.T) {
		pm := NewPatternMatcher(logger)
		err := pm.ValidatePatterns()
		if err == nil {
			t.Error("Expected error for no patterns configured")
		}
		if !contains(err.Error(), "no domain patterns configured") {
			t.Errorf("Expected error message about no patterns, got: %s", err.Error())
		}
	})

	t.Run("valid patterns", func(t *testing.T) {
		pm := NewPatternMatcher(logger)
		patterns := []string{
			"*.sankalpmukim.dev",
			"*.example.com",
			"app.test.local",
		}

		for _, pattern := range patterns {
			if err := pm.AddPattern(pattern); err != nil {
				t.Fatalf("Failed to add pattern '%s': %v", pattern, err)
			}
		}

		err := pm.ValidatePatterns()
		if err != nil {
			t.Errorf("Unexpected error for valid patterns: %v", err)
		}
	})
}

// TestPatternMatcher_GetPatterns tests getting configured patterns
func TestPatternMatcher_GetPatterns(t *testing.T) {
	logger := NewStructuredLogger(log.New(io.Discard, "", 0))
	pm := NewPatternMatcher(logger)

	// Initially should be empty
	patterns := pm.GetPatterns()
	if len(patterns) != 0 {
		t.Errorf("Expected empty patterns, got %d patterns", len(patterns))
	}

	// Add some patterns
	testPatterns := []string{
		"*.sankalpmukim.dev",
		"*.example.com",
		"app.test.local",
	}

	for _, pattern := range testPatterns {
		if err := pm.AddPattern(pattern); err != nil {
			t.Fatalf("Failed to add pattern '%s': %v", pattern, err)
		}
	}

	// Get patterns and verify
	patterns = pm.GetPatterns()
	if len(patterns) != len(testPatterns) {
		t.Errorf("Expected %d patterns, got %d", len(testPatterns), len(patterns))
	}

	// Verify patterns match
	for i, expected := range testPatterns {
		if i >= len(patterns) || patterns[i] != expected {
			t.Errorf("Pattern %d: expected '%s', got '%s'", i, expected, patterns[i])
		}
	}

	// Verify it's a copy (modifying returned slice shouldn't affect internal state)
	patterns[0] = "modified.pattern.com"
	originalPatterns := pm.GetPatterns()
	if originalPatterns[0] == "modified.pattern.com" {
		t.Error("GetPatterns should return a copy, not the original slice")
	}
}

// TestPatternMatcher_ConvertPatternToRegex tests regex conversion
func TestPatternMatcher_ConvertPatternToRegex(t *testing.T) {
	logger := NewStructuredLogger(log.New(io.Discard, "", 0))
	pm := NewPatternMatcher(logger)

	tests := []struct {
		name          string
		pattern       string
		expectedRegex string
		expectError   bool
	}{
		{
			name:          "wildcard pattern",
			pattern:       "*.sankalpmukim.dev",
			expectedRegex: "^(\\d+)\\.sankalpmukim\\.dev$",
			expectError:   false,
		},
		{
			name:          "wildcard pattern with subdomain",
			pattern:       "*.api.example.com",
			expectedRegex: "^(\\d+)\\.api\\.example\\.com$",
			expectError:   false,
		},
		{
			name:          "exact pattern",
			pattern:       "app.example.com",
			expectedRegex: "^app\\.example\\.com$",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regex, err := pm.convertPatternToRegex(tt.pattern)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for pattern '%s', but got none", tt.pattern)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for pattern '%s': %v", tt.pattern, err)
				}
				if regex != tt.expectedRegex {
					t.Errorf("convertPatternToRegex(%s) = '%s', expected '%s'", tt.pattern, regex, tt.expectedRegex)
				}
			}
		})
	}
}

// TestPatternMatcher_Integration tests integration scenarios
func TestPatternMatcher_Integration(t *testing.T) {
	logger := NewStructuredLogger(log.New(io.Discard, "", 0))
	pm := NewPatternMatcher(logger)

	// Add multiple patterns
	patterns := []string{
		"*.sankalpmukim.dev",
		"*.localhost",
		"*.test.local",
		"api.example.com",
	}

	for _, pattern := range patterns {
		if err := pm.AddPattern(pattern); err != nil {
			t.Fatalf("Failed to add pattern '%s': %v", pattern, err)
		}
	}

	// Test various hosts
	testCases := []struct {
		host          string
		shouldMatch   bool
		expectedPort  int
		shouldExtract bool
	}{
		{"3000.sankalpmukim.dev", true, 3000, true},
		{"8080.localhost", true, 8080, true},
		{"5173.test.local", true, 5173, true},
		{"api.example.com", true, 0, false}, // exact match, no port extraction
		{"9000.different.com", false, 0, false},
		{"invalid-format", false, 0, false},
		{"65535.sankalpmukim.dev", true, 65535, true},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("host_%s", tc.host), func(t *testing.T) {
			// Test pattern matching
			matches := pm.MatchesPattern(tc.host)
			if matches != tc.shouldMatch {
				t.Errorf("MatchesPattern(%s) = %v, expected %v", tc.host, matches, tc.shouldMatch)
			}

			// Test port extraction
			port, ok := pm.ExtractPort(tc.host)
			if ok != tc.shouldExtract {
				t.Errorf("ExtractPort(%s) ok = %v, expected %v", tc.host, ok, tc.shouldExtract)
			}
			if tc.shouldExtract && port != tc.expectedPort {
				t.Errorf("ExtractPort(%s) port = %d, expected %d", tc.host, port, tc.expectedPort)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
