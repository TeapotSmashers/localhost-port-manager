package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestModeAwareHandler tests the mode-aware request handler system
func TestModeAwareHandler(t *testing.T) {
	// Create a test logger
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	tests := []struct {
		name           string
		mode           DeploymentMode
		config         *Config
		host           string
		expectedStatus int
		expectedTarget string
		shouldRedirect bool
	}{
		{
			name: "Local mode valid request",
			mode: LocalMode,
			config: &Config{
				DeploymentMode: LocalMode,
				Ports:          []int{3000, 8080},
			},
			host:           "3000.local",
			expectedStatus: http.StatusMovedPermanently,
			expectedTarget: "http://localhost:3000",
			shouldRedirect: true,
		},
		{
			name: "Local mode invalid host",
			mode: LocalMode,
			config: &Config{
				DeploymentMode: LocalMode,
				Ports:          []int{3000, 8080},
			},
			host:           "invalid.host",
			expectedStatus: http.StatusNotFound,
			shouldRedirect: false,
		},
		{
			name: "Web service mode valid request",
			mode: WebServiceMode,
			config: &Config{
				DeploymentMode: WebServiceMode,
				Ports:          []int{3000, 8080},
				DomainPatterns: []string{"*.example.com"},
			},
			host:           "3000.example.com",
			expectedStatus: http.StatusMovedPermanently,
			expectedTarget: "http://localhost:3000",
			shouldRedirect: true,
		},
		{
			name: "Web service mode domain pattern mismatch",
			mode: WebServiceMode,
			config: &Config{
				DeploymentMode: WebServiceMode,
				Ports:          []int{3000, 8080},
				DomainPatterns: []string{"*.example.com"},
			},
			host:           "3000.other.com",
			expectedStatus: http.StatusBadRequest,
			shouldRedirect: false,
		},
		{
			name: "Port not configured",
			mode: LocalMode,
			config: &Config{
				DeploymentMode: LocalMode,
				Ports:          []int{3000, 8080},
			},
			host:           "9000.local",
			expectedStatus: http.StatusNotFound,
			shouldRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mode-aware handler
			handler := NewModeAwareHandler(tt.mode, tt.config, structuredLogger, securityValidator)

			// Create test request
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()

			// Handle the request
			handler.HandleRequest(w, req)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Check redirect target if expected
			if tt.shouldRedirect {
				location := w.Header().Get("Location")
				if location != tt.expectedTarget {
					t.Errorf("Expected redirect to %s, got %s", tt.expectedTarget, location)
				}
			}
		})
	}
}

// TestLocalHandler tests the local handler functionality
func TestLocalHandler(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	config := &Config{
		DeploymentMode: LocalMode,
		Ports:          []int{3000, 8080, 5173},
	}

	handler := NewLocalHandler(config, structuredLogger, securityValidator)

	tests := []struct {
		name           string
		host           string
		expectedStatus int
		expectedTarget string
		shouldRedirect bool
	}{
		{
			name:           "Valid local domain",
			host:           "3000.local",
			expectedStatus: http.StatusMovedPermanently,
			expectedTarget: "http://localhost:3000",
			shouldRedirect: true,
		},
		{
			name:           "Valid dev domain",
			host:           "8080.dev",
			expectedStatus: http.StatusMovedPermanently,
			expectedTarget: "http://localhost:8080",
			shouldRedirect: true,
		},
		{
			name:           "Invalid host format",
			host:           "invalid.host",
			expectedStatus: http.StatusNotFound,
			shouldRedirect: false,
		},
		{
			name:           "Port not configured",
			host:           "9000.local",
			expectedStatus: http.StatusNotFound,
			shouldRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()

			handler.HandleRequest(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.shouldRedirect {
				location := w.Header().Get("Location")
				if location != tt.expectedTarget {
					t.Errorf("Expected redirect to %s, got %s", tt.expectedTarget, location)
				}
			}
		})
	}
}

// TestWebServiceHandler tests the web service handler functionality
func TestWebServiceHandler(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	config := &Config{
		DeploymentMode: WebServiceMode,
		Ports:          []int{3000, 8080, 5173},
		DomainPatterns: []string{"*.example.com", "*.test.dev"},
	}

	// Create domain matcher
	domainMatcher := NewPatternMatcher(structuredLogger)
	for _, pattern := range config.DomainPatterns {
		err := domainMatcher.AddPattern(pattern)
		if err != nil {
			t.Fatalf("Failed to add pattern %s: %v", pattern, err)
		}
	}

	handler := NewWebServiceHandler(domainMatcher, config, structuredLogger, securityValidator)

	tests := []struct {
		name           string
		host           string
		expectedStatus int
		expectedTarget string
		shouldRedirect bool
	}{
		{
			name:           "Valid web service request",
			host:           "3000.example.com",
			expectedStatus: http.StatusMovedPermanently,
			expectedTarget: "http://localhost:3000",
			shouldRedirect: true,
		},
		{
			name:           "Valid alternative domain",
			host:           "8080.test.dev",
			expectedStatus: http.StatusMovedPermanently,
			expectedTarget: "http://localhost:8080",
			shouldRedirect: true,
		},
		{
			name:           "Domain pattern mismatch",
			host:           "3000.other.com",
			expectedStatus: http.StatusBadRequest,
			shouldRedirect: false,
		},
		{
			name:           "Port not configured",
			host:           "9000.example.com",
			expectedStatus: http.StatusNotFound,
			shouldRedirect: false,
		},
		{
			name:           "Invalid port format",
			host:           "invalid.example.com",
			expectedStatus: http.StatusBadRequest,
			shouldRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()

			handler.HandleRequest(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.shouldRedirect {
				location := w.Header().Get("Location")
				if location != tt.expectedTarget {
					t.Errorf("Expected redirect to %s, got %s", tt.expectedTarget, location)
				}
			}
		})
	}
}

// TestRequestValidation tests request validation for both modes
func TestRequestValidation(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	// Test local handler validation
	localConfig := &Config{
		DeploymentMode: LocalMode,
		Ports:          []int{3000},
	}
	localHandler := NewLocalHandler(localConfig, structuredLogger, securityValidator)

	// Test web service handler validation
	webConfig := &Config{
		DeploymentMode: WebServiceMode,
		Ports:          []int{3000},
		DomainPatterns: []string{"*.example.com"},
	}
	domainMatcher := NewPatternMatcher(structuredLogger)
	domainMatcher.AddPattern("*.example.com")
	webHandler := NewWebServiceHandler(domainMatcher, webConfig, structuredLogger, securityValidator)

	tests := []struct {
		name        string
		handler     RequestHandler
		host        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Local handler valid host",
			handler:     localHandler,
			host:        "3000.local",
			expectError: false,
		},
		{
			name:        "Web handler valid host",
			handler:     webHandler,
			host:        "3000.example.com",
			expectError: false,
		},
		{
			name:        "Web handler invalid domain",
			handler:     webHandler,
			host:        "3000.other.com",
			expectError: true,
			errorMsg:    "does not match any configured domain patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
			req.Host = tt.host

			err := tt.handler.ValidateRequest(req)

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

// TestProcessRedirect tests redirect processing for both modes
func TestProcessRedirect(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	configuredPorts := []int{3000, 8080, 5173}

	// Test local handler
	localConfig := &Config{
		DeploymentMode: LocalMode,
		Ports:          configuredPorts,
	}
	localHandler := NewLocalHandler(localConfig, structuredLogger, securityValidator)

	// Test web service handler
	webConfig := &Config{
		DeploymentMode: WebServiceMode,
		Ports:          configuredPorts,
		DomainPatterns: []string{"*.example.com"},
	}
	domainMatcher := NewPatternMatcher(structuredLogger)
	domainMatcher.AddPattern("*.example.com")
	webHandler := NewWebServiceHandler(domainMatcher, webConfig, structuredLogger, securityValidator)

	tests := []struct {
		name         string
		handler      RequestHandler
		host         string
		expectedURL  string
		expectedPort int
		expectError  bool
	}{
		{
			name:         "Local handler valid redirect",
			handler:      localHandler,
			host:         "3000.local",
			expectedURL:  "http://localhost:3000",
			expectedPort: 3000,
			expectError:  false,
		},
		{
			name:         "Web handler valid redirect",
			handler:      webHandler,
			host:         "8080.example.com",
			expectedURL:  "http://localhost:8080",
			expectedPort: 8080,
			expectError:  false,
		},
		{
			name:        "Local handler invalid host",
			handler:     localHandler,
			host:        "invalid.host",
			expectError: true,
		},
		{
			name:        "Web handler port not configured",
			handler:     webHandler,
			host:        "9000.example.com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, port, err := tt.handler.ProcessRedirect(tt.host, configuredPorts)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if url != tt.expectedURL {
					t.Errorf("Expected URL %s, got %s", tt.expectedURL, url)
				}
				if port != tt.expectedPort {
					t.Errorf("Expected port %d, got %d", tt.expectedPort, port)
				}
			}
		})
	}
}

// TestSecurityHeaders tests that security headers are properly set
func TestSecurityHeaders(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	config := &Config{
		DeploymentMode: LocalMode,
		Ports:          []int{3000},
	}

	handler := NewLocalHandler(config, structuredLogger, securityValidator)

	req := httptest.NewRequest("GET", "http://3000.local/", nil)
	req.Host = "3000.local"
	w := httptest.NewRecorder()

	handler.HandleRequest(w, req)

	// Check that security headers are set
	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
		"Cache-Control":          "no-cache, no-store, must-revalidate",
	}

	for header, expectedValue := range expectedHeaders {
		actualValue := w.Header().Get(header)
		if actualValue != expectedValue {
			t.Errorf("Expected header %s to be %s, got %s", header, expectedValue, actualValue)
		}
	}
}

// TestModeAwareHandlerInitialization tests proper initialization of mode-aware handler
func TestModeAwareHandlerInitialization(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	tests := []struct {
		name   string
		mode   DeploymentMode
		config *Config
	}{
		{
			name: "Local mode initialization",
			mode: LocalMode,
			config: &Config{
				DeploymentMode: LocalMode,
				Ports:          []int{3000, 8080},
			},
		},
		{
			name: "Web service mode initialization",
			mode: WebServiceMode,
			config: &Config{
				DeploymentMode: WebServiceMode,
				Ports:          []int{3000, 8080},
				DomainPatterns: []string{"*.example.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewModeAwareHandler(tt.mode, tt.config, structuredLogger, securityValidator)

			if handler == nil {
				t.Errorf("Handler should not be nil")
			}

			if handler.mode != tt.mode {
				t.Errorf("Expected mode %v, got %v", tt.mode, handler.mode)
			}

			// Test that appropriate sub-handlers are initialized
			switch tt.mode {
			case LocalMode:
				if handler.localHandler == nil {
					t.Errorf("Local handler should be initialized for local mode")
				}
			case WebServiceMode:
				if handler.webHandler == nil {
					t.Errorf("Web handler should be initialized for web service mode")
				}
			}
		})
	}
}
