package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestEnhancedStatusEndpoint tests the enhanced status endpoint with deployment mode and web service metrics
func TestEnhancedStatusEndpoint(t *testing.T) {
	// Create test environment
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	// Create test service
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	config := &Config{
		Ports:           []int{3000, 8080},
		ConfigFilePath:  env.MockConfigFile,
		HostsBackupPath: env.MockHostsFile + ".backup",
		DeploymentMode:  LocalMode,
		WebServicePort:  8080,
		DomainPatterns:  []string{"*.example.com"},
		EnableRateLimit: false,
		RateLimitRPS:    100,
	}

	service := &PortRedirectService{
		config:            config,
		logger:            logger,
		structuredLogger:  structuredLogger,
		securityValidator: securityValidator,
		startTime:         time.Now().Add(-1 * time.Hour), // 1 hour uptime
		configLoaded:      time.Now().Add(-30 * time.Minute),
	}

	service.hostsManager = NewHostsManager(env.MockHostsFile, config.HostsBackupPath)

	t.Run("Status JSON includes deployment mode", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/status?format=json", nil)
		w := httptest.NewRecorder()

		service.handleStatus(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body := w.Body.String()
		if !strings.Contains(body, "deployment_mode") {
			t.Errorf("Response should contain deployment_mode field")
		}

		if !strings.Contains(body, "local") {
			t.Errorf("Response should contain local deployment mode")
		}
	})

	t.Run("Status HTML includes deployment mode", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/status", nil)
		w := httptest.NewRecorder()

		service.handleStatus(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Deployment Mode") {
			t.Errorf("Response should contain Deployment Mode section")
		}

		if !strings.Contains(body, "local") {
			t.Errorf("Response should show local deployment mode")
		}
	})
}

// TestWebServiceMetrics tests web service specific metrics tracking
func TestWebServiceMetrics(t *testing.T) {
	// Create test environment
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	// Create test service in web service mode
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	config := &Config{
		Ports:           []int{3000, 8080},
		ConfigFilePath:  env.MockConfigFile,
		HostsBackupPath: env.MockHostsFile + ".backup",
		DeploymentMode:  WebServiceMode,
		WebServicePort:  8080,
		DomainPatterns:  []string{"*.example.com"},
		EnableRateLimit: true,
		RateLimitRPS:    100,
	}

	service := &PortRedirectService{
		config:            config,
		logger:            logger,
		structuredLogger:  structuredLogger,
		securityValidator: securityValidator,
		startTime:         time.Now().Add(-1 * time.Hour),
		configLoaded:      time.Now().Add(-30 * time.Minute),
	}

	// Initialize hosts manager
	service.hostsManager = NewHostsManager(env.MockHostsFile, config.HostsBackupPath)

	// Initialize mode-aware request handler
	service.requestHandler = NewModeAwareHandler(config.DeploymentMode, config, structuredLogger, securityValidator)

	t.Run("Web service metrics are tracked", func(t *testing.T) {
		// Get initial status
		status := service.GetServiceStatus()

		if status.DeploymentMode != "web" {
			t.Errorf("Expected deployment mode 'web', got '%s'", status.DeploymentMode)
		}

		if status.WebServiceMetrics == nil {
			t.Errorf("Web service metrics should not be nil in web service mode")
		}

		if len(status.WebServiceMetrics.DomainPatterns) == 0 {
			t.Errorf("Domain patterns should be populated")
		}

		if status.WebServiceMetrics.DomainPatterns[0] != "*.example.com" {
			t.Errorf("Expected domain pattern '*.example.com', got '%s'", status.WebServiceMetrics.DomainPatterns[0])
		}
	})

	t.Run("Status JSON includes web service metrics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/status?format=json", nil)
		w := httptest.NewRecorder()

		service.handleStatus(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body := w.Body.String()
		if !strings.Contains(body, "web_service_metrics") {
			t.Errorf("Response should contain web_service_metrics field")
		}

		if !strings.Contains(body, "domain_patterns") {
			t.Errorf("Response should contain domain_patterns field")
		}

		if !strings.Contains(body, "request_count") {
			t.Errorf("Response should contain request_count field")
		}
	})

	t.Run("Status HTML includes web service metrics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/status", nil)
		w := httptest.NewRecorder()

		service.handleStatus(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Web Service Metrics") {
			t.Errorf("Response should contain Web Service Metrics section")
		}

		if !strings.Contains(body, "Domain Patterns") {
			t.Errorf("Response should contain Domain Patterns field")
		}

		if !strings.Contains(body, "Total Requests") {
			t.Errorf("Response should contain Total Requests field")
		}
	})
}

// TestHealthEndpoint tests the health check endpoint
func TestHealthEndpoint(t *testing.T) {
	// Create test environment
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	// Create test service
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	config := &Config{
		Ports:           []int{3000, 8080},
		ConfigFilePath:  env.MockConfigFile,
		HostsBackupPath: env.MockHostsFile + ".backup",
		DeploymentMode:  LocalMode,
		WebServicePort:  8080,
		DomainPatterns:  []string{"*.example.com"},
		EnableRateLimit: false,
		RateLimitRPS:    100,
	}

	service := &PortRedirectService{
		config:            config,
		logger:            logger,
		structuredLogger:  structuredLogger,
		securityValidator: securityValidator,
		startTime:         time.Now().Add(-1 * time.Hour),
		configLoaded:      time.Now().Add(-30 * time.Minute),
	}

	service.hostsManager = NewHostsManager(env.MockHostsFile, config.HostsBackupPath)

	// Create backup file and add expected entries to make the service healthy
	service.hostsManager.CreateBackup()
	service.hostsManager.AddPortEntries(config.Ports)

	t.Run("Health endpoint returns OK for healthy service", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		service.handleHealth(w, req)

		resp := w.Result()
		body := w.Body.String()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		if !strings.Contains(body, "OK") {
			t.Errorf("Response should contain 'OK' for healthy service")
		}

		if !strings.Contains(body, "local mode") {
			t.Errorf("Response should indicate local mode")
		}
	})

	t.Run("Health endpoint JSON format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health?format=json", nil)
		w := httptest.NewRecorder()

		service.handleHealth(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", contentType)
		}

		body := w.Body.String()
		if !strings.Contains(body, "status") {
			t.Errorf("JSON response should contain status field")
		}

		if !strings.Contains(body, "deployment_mode") {
			t.Errorf("JSON response should contain deployment_mode field")
		}

		if !strings.Contains(body, "uptime") {
			t.Errorf("JSON response should contain uptime field")
		}
	})

	t.Run("Health endpoint with Accept header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		service.handleHealth(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", contentType)
		}
	})

	t.Run("Health endpoint returns unhealthy for service with errors", func(t *testing.T) {
		// Set an error in the service
		service.SetLastError("Test error")

		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		service.handleHealth(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("Expected status 503, got %d", resp.StatusCode)
		}

		body := w.Body.String()
		if !strings.Contains(body, "UNHEALTHY") {
			t.Errorf("Response should contain 'UNHEALTHY' for service with errors")
		}

		// Clear the error
		service.ClearLastError()
	})
}

// TestWebServiceMetricsTracking tests that metrics are properly tracked during request processing
func TestWebServiceMetricsTracking(t *testing.T) {
	// Create test environment
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	// Create test service in web service mode
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	config := &Config{
		Ports:           []int{3000, 8080},
		ConfigFilePath:  env.MockConfigFile,
		HostsBackupPath: env.MockHostsFile + ".backup",
		DeploymentMode:  WebServiceMode,
		WebServicePort:  8080,
		DomainPatterns:  []string{"*.example.com"},
		EnableRateLimit: false,
		RateLimitRPS:    100,
	}

	// Create domain matcher
	domainMatcher := NewPatternMatcher(structuredLogger)
	domainMatcher.AddPattern("*.example.com")

	// Create web service handler
	webHandler := NewWebServiceHandler(domainMatcher, config, structuredLogger, securityValidator)

	t.Run("Metrics tracking methods work correctly", func(t *testing.T) {
		// Track some requests
		webHandler.TrackRequest("192.168.1.1")
		webHandler.TrackRequest("192.168.1.2")
		webHandler.TrackSuccessfulRedirect(3000)
		webHandler.TrackSuccessfulRedirect(8080)
		webHandler.TrackFailedRequest()
		webHandler.TrackRateLimitedRequest()

		// Get metrics
		metrics := webHandler.GetMetrics()

		if metrics.RequestCount != 2 {
			t.Errorf("Expected request count 2, got %d", metrics.RequestCount)
		}

		if metrics.SuccessfulRedirects != 2 {
			t.Errorf("Expected successful redirects 2, got %d", metrics.SuccessfulRedirects)
		}

		if metrics.FailedRequests != 1 {
			t.Errorf("Expected failed requests 1, got %d", metrics.FailedRequests)
		}

		if metrics.RateLimitedRequests != 1 {
			t.Errorf("Expected rate limited requests 1, got %d", metrics.RateLimitedRequests)
		}

		if metrics.PortUsageStats["3000"] != 1 {
			t.Errorf("Expected port 3000 usage 1, got %d", metrics.PortUsageStats["3000"])
		}

		if metrics.PortUsageStats["8080"] != 1 {
			t.Errorf("Expected port 8080 usage 1, got %d", metrics.PortUsageStats["8080"])
		}

		if metrics.LastRequestTime == nil {
			t.Errorf("Last request time should not be nil")
		}
	})

	t.Run("Metrics are thread-safe", func(t *testing.T) {
		// Test concurrent access to metrics
		done := make(chan bool, 10)

		// Start multiple goroutines to track metrics
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- true }()
				webHandler.TrackRequest("192.168.1.100")
				webHandler.TrackSuccessfulRedirect(3000)
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify metrics were tracked correctly
		metrics := webHandler.GetMetrics()
		if metrics.RequestCount < 10 {
			t.Errorf("Expected at least 10 more requests, got total %d", metrics.RequestCount)
		}

		if metrics.SuccessfulRedirects < 10 {
			t.Errorf("Expected at least 10 more successful redirects, got total %d", metrics.SuccessfulRedirects)
		}
	})
}

// TestHealthEndpointWebServiceMode tests health endpoint in web service mode
func TestHealthEndpointWebServiceMode(t *testing.T) {
	// Create test environment
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	// Create test service in web service mode
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	config := &Config{
		Ports:           []int{3000, 8080},
		ConfigFilePath:  env.MockConfigFile,
		HostsBackupPath: env.MockHostsFile + ".backup",
		DeploymentMode:  WebServiceMode,
		WebServicePort:  8080,
		DomainPatterns:  []string{"*.example.com"},
		EnableRateLimit: true,
		RateLimitRPS:    100,
	}

	service := &PortRedirectService{
		config:            config,
		logger:            logger,
		structuredLogger:  structuredLogger,
		securityValidator: securityValidator,
		startTime:         time.Now().Add(-1 * time.Hour),
		configLoaded:      time.Now().Add(-30 * time.Minute),
	}

	// Initialize hosts manager
	service.hostsManager = NewHostsManager(env.MockHostsFile, config.HostsBackupPath)

	// Initialize mode-aware request handler
	service.requestHandler = NewModeAwareHandler(config.DeploymentMode, config, structuredLogger, securityValidator)

	t.Run("Health endpoint shows web service specific info", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health?format=json", nil)
		w := httptest.NewRecorder()

		service.handleHealth(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body := w.Body.String()

		// Parse JSON to verify structure
		var healthResponse map[string]interface{}
		if err := json.Unmarshal([]byte(body), &healthResponse); err != nil {
			t.Errorf("Failed to parse JSON response: %v", err)
		}

		if healthResponse["deployment_mode"] != "web" {
			t.Errorf("Expected deployment_mode 'web', got '%v'", healthResponse["deployment_mode"])
		}

		if _, exists := healthResponse["request_count"]; !exists {
			t.Errorf("Health response should include request_count for web service mode")
		}

		if _, exists := healthResponse["domain_patterns_count"]; !exists {
			t.Errorf("Health response should include domain_patterns_count for web service mode")
		}
	})
}
