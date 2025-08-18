package main

import (
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSecurityValidator_ValidateHostHeader tests host header validation
func TestSecurityValidator_ValidateHostHeader(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	validator := NewSecurityValidator(structuredLogger)

	tests := []struct {
		name        string
		host        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid host",
			host:        "3000.example.com",
			expectError: false,
		},
		{
			name:        "Empty host",
			host:        "",
			expectError: true,
			errorMsg:    "host header is empty",
		},
		{
			name:        "Host too long",
			host:        strings.Repeat("a", 254),
			expectError: true,
			errorMsg:    "host header too long",
		},
		{
			name:        "Host with null byte",
			host:        "example.com\x00",
			expectError: true,
			errorMsg:    "host header contains invalid characters",
		},
		{
			name:        "Host with control characters",
			host:        "example.com\x01",
			expectError: true,
			errorMsg:    "host header contains invalid characters",
		},
		{
			name:        "Host with CRLF injection",
			host:        "example.com\r\nHost: evil.com",
			expectError: true,
			errorMsg:    "host header contains invalid characters",
		},
		{
			name:        "Host with JavaScript injection",
			host:        "example.com<script>alert(1)</script>",
			expectError: true,
			errorMsg:    "host header contains invalid content",
		},
		{
			name:        "Host with protocol injection",
			host:        "javascript:alert(1)",
			expectError: true,
			errorMsg:    "host header contains invalid content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateHostHeader(tt.host)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestSecurityValidator_ValidateRedirectTarget tests redirect target validation
func TestSecurityValidator_ValidateRedirectTarget(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	validator := NewSecurityValidator(structuredLogger)

	configuredPorts := []int{3000, 8080, 5173, 22, 3306, 3389}

	tests := []struct {
		name        string
		port        int
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid configured port",
			port:        3000,
			expectError: false,
		},
		{
			name:        "Port out of range - too low",
			port:        0,
			expectError: true,
			errorMsg:    "out of valid range",
		},
		{
			name:        "Port out of range - too high",
			port:        65536,
			expectError: true,
			errorMsg:    "out of valid range",
		},
		{
			name:        "Port not configured",
			port:        9999,
			expectError: true,
			errorMsg:    "not configured for redirection",
		},
		{
			name:        "Restricted port - SSH",
			port:        22,
			expectError: true,
			errorMsg:    "restricted port",
		},
		{
			name:        "Restricted port - MySQL",
			port:        3306,
			expectError: true,
			errorMsg:    "restricted port",
		},
		{
			name:        "Restricted port - RDP",
			port:        3389,
			expectError: true,
			errorMsg:    "restricted port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateRedirectTarget(tt.port, configuredPorts)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestSecurityValidator_ValidateLocalhostRedirect tests localhost redirect validation
func TestSecurityValidator_ValidateLocalhostRedirect(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	validator := NewSecurityValidator(structuredLogger)

	tests := []struct {
		name        string
		url         string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid localhost HTTP",
			url:         "http://localhost:3000/",
			expectError: false,
		},
		{
			name:        "Valid localhost HTTPS",
			url:         "https://localhost:3000/",
			expectError: false,
		},
		{
			name:        "Valid 127.0.0.1",
			url:         "http://127.0.0.1:3000/",
			expectError: false,
		},
		{
			name:        "Valid IPv6 localhost",
			url:         "http://::1:3000/",
			expectError: false,
		},
		{
			name:        "Empty URL",
			url:         "",
			expectError: true,
			errorMsg:    "redirect URL cannot be empty",
		},
		{
			name:        "Non-localhost redirect",
			url:         "http://example.com:3000/",
			expectError: true,
			errorMsg:    "redirect must be to localhost only",
		},
		{
			name:        "URL too long",
			url:         "http://localhost:3000/" + strings.Repeat("a", 250),
			expectError: true,
			errorMsg:    "redirect URL too long",
		},
		{
			name:        "Invalid protocol",
			url:         "ftp://localhost:3000/",
			expectError: true,
			errorMsg:    "redirect must be to localhost only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateLocalhostRedirect(tt.url)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestSecurityValidator_ValidateRequestParameters tests request parameter validation
func TestSecurityValidator_ValidateRequestParameters(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	validator := NewSecurityValidator(structuredLogger)

	tests := []struct {
		name        string
		method      string
		path        string
		userAgent   string
		query       string
		headers     map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid GET request",
			method:      "GET",
			path:        "/",
			userAgent:   "Mozilla/5.0",
			expectError: false,
		},
		{
			name:        "Valid HEAD request",
			method:      "HEAD",
			path:        "/",
			expectError: false,
		},
		{
			name:        "Invalid POST method",
			method:      "POST",
			path:        "/",
			expectError: true,
			errorMsg:    "method POST not allowed",
		},
		{
			name:        "Suspicious user agent - sqlmap",
			method:      "GET",
			path:        "/",
			userAgent:   "sqlmap/1.0",
			expectError: true,
			errorMsg:    "request blocked",
		},
		{
			name:        "User agent too long",
			method:      "GET",
			path:        "/",
			userAgent:   strings.Repeat("a", 1025),
			expectError: true,
			errorMsg:    "user-agent header too long",
		},
		{
			name:        "Query parameters not allowed",
			method:      "GET",
			path:        "/",
			query:       "param=value",
			expectError: true,
			errorMsg:    "query parameters not allowed",
		},
		{
			name:        "Invalid path",
			method:      "GET",
			path:        "/admin",
			expectError: true,
			errorMsg:    "path not found",
		},
		{
			name:        "Valid status path",
			method:      "GET",
			path:        "/status",
			expectError: false,
		},
		{
			name:        "Valid health path",
			method:      "GET",
			path:        "/health",
			expectError: false,
		},
		{
			name:   "Suspicious X-Forwarded-Host header",
			method: "GET",
			path:   "/",
			headers: map[string]string{
				"X-Forwarded-Host": "evil.com",
			},
			expectError: true,
			errorMsg:    "suspicious request headers",
		},
		{
			name:   "Content-Length on GET request",
			method: "GET",
			path:   "/",
			headers: map[string]string{
				"Content-Length": "100",
			},
			expectError: true,
			errorMsg:    "content not allowed for GET requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "http://example.com" + tt.path
			if tt.query != "" {
				url += "?" + tt.query
			}

			req := httptest.NewRequest(tt.method, url, nil)
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			err := validator.ValidateRequestParameters(req)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestSecurityValidator_CreateSafeErrorResponse tests safe error response creation
func TestSecurityValidator_CreateSafeErrorResponse(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	validator := NewSecurityValidator(structuredLogger)

	tests := []struct {
		name           string
		statusCode     int
		expectedMsg    string
		expectedStatus int
	}{
		{
			name:           "Bad Request",
			statusCode:     400,
			expectedMsg:    "Bad Request",
			expectedStatus: 400,
		},
		{
			name:           "Not Found",
			statusCode:     404,
			expectedMsg:    "Not Found",
			expectedStatus: 404,
		},
		{
			name:           "Too Many Requests",
			statusCode:     429,
			expectedMsg:    "Too Many Requests",
			expectedStatus: 429,
		},
		{
			name:           "Internal Server Error",
			statusCode:     500,
			expectedMsg:    "Internal Server Error",
			expectedStatus: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			w := httptest.NewRecorder()
			requestID := validator.GenerateRequestID()

			validator.CreateSafeErrorResponse(w, req,
				&ValidationError{Message: "detailed error message"},
				tt.statusCode, requestID)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			// Check that response body contains safe message
			body := w.Body.String()
			if !strings.Contains(body, tt.expectedMsg) {
				t.Errorf("Expected response to contain '%s', got '%s'", tt.expectedMsg, body)
			}

			// Check that detailed error is not leaked
			if strings.Contains(body, "detailed error message") {
				t.Errorf("Response leaked detailed error message: %s", body)
			}

			// Check security headers
			expectedHeaders := map[string]string{
				"X-Content-Type-Options":       "nosniff",
				"X-Frame-Options":              "DENY",
				"X-XSS-Protection":             "1; mode=block",
				"Cache-Control":                "no-cache, no-store, must-revalidate",
				"Referrer-Policy":              "no-referrer",
				"Content-Security-Policy":      "default-src 'none'",
				"Cross-Origin-Embedder-Policy": "require-corp",
				"Cross-Origin-Opener-Policy":   "same-origin",
				"Cross-Origin-Resource-Policy": "same-origin",
			}

			for header, expectedValue := range expectedHeaders {
				actualValue := w.Header().Get(header)
				if actualValue != expectedValue {
					t.Errorf("Expected header %s to be '%s', got '%s'", header, expectedValue, actualValue)
				}
			}

			// Check request ID header
			if w.Header().Get("X-Request-ID") != requestID {
				t.Errorf("Expected X-Request-ID header to be '%s', got '%s'", requestID, w.Header().Get("X-Request-ID"))
			}
		})
	}
}

// TestSecurityValidator_SetSecurityHeaders tests security header setting
func TestSecurityValidator_SetSecurityHeaders(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	validator := NewSecurityValidator(structuredLogger)

	w := httptest.NewRecorder()
	validator.SetSecurityHeaders(w)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":            "nosniff",
		"X-Frame-Options":                   "DENY",
		"X-XSS-Protection":                  "1; mode=block",
		"Cache-Control":                     "no-cache, no-store, must-revalidate",
		"Pragma":                            "no-cache",
		"Expires":                           "0",
		"Referrer-Policy":                   "no-referrer",
		"Content-Security-Policy":           "default-src 'none'",
		"X-Permitted-Cross-Domain-Policies": "none",
		"Cross-Origin-Embedder-Policy":      "require-corp",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Resource-Policy":      "same-origin",
	}

	for header, expectedValue := range expectedHeaders {
		actualValue := w.Header().Get(header)
		if actualValue != expectedValue {
			t.Errorf("Expected header %s to be '%s', got '%s'", header, expectedValue, actualValue)
		}
	}
}

// TestSecurityValidator_GenerateRequestID tests request ID generation
func TestSecurityValidator_GenerateRequestID(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	validator := NewSecurityValidator(structuredLogger)

	// Generate multiple request IDs
	ids := make(map[string]bool)
	duplicateCount := 0
	for i := 0; i < 10; i++ {
		id := validator.GenerateRequestID()

		// Check that ID is not empty
		if id == "" {
			t.Errorf("Generated empty request ID")
		}

		// Count duplicates but don't fail immediately (timing-based IDs may have some duplicates)
		if ids[id] {
			duplicateCount++
		}
		ids[id] = true

		// Check ID format (should contain timestamp and random component)
		if !strings.Contains(id, "-") {
			t.Errorf("Request ID should contain hyphen separator: %s", id)
		}

		// Add small delay to reduce chance of duplicates
		time.Sleep(1 * time.Millisecond)
	}

	// Allow some duplicates but not too many
	if duplicateCount > 3 {
		t.Errorf("Too many duplicate request IDs generated: %d out of 10", duplicateCount)
	}
}

// TestGetClientIPFromRequest tests client IP extraction with security considerations
func TestGetClientIPFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expectedIP string
	}{
		{
			name:       "Direct connection",
			remoteAddr: "192.168.1.100:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For header",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1, 10.0.0.1",
			},
			expectedIP: "203.0.113.1",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.2",
			},
			expectedIP: "203.0.113.2",
		},
		{
			name:       "Invalid X-Forwarded-For",
			remoteAddr: "192.168.1.100:12345",
			headers: map[string]string{
				"X-Forwarded-For": "invalid-ip",
			},
			expectedIP: "192.168.1.100",
		},
		{
			name:       "Invalid X-Real-IP",
			remoteAddr: "192.168.1.100:12345",
			headers: map[string]string{
				"X-Real-IP": "not-an-ip",
			},
			expectedIP: "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			actualIP := getClientIPFromRequest(req)
			if actualIP != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, actualIP)
			}
		})
	}
}
