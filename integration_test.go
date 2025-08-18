package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIntegrationEnvironment provides an integration test environment
type TestIntegrationEnvironment struct {
	TempDir    string
	ConfigFile string
	HostsFile  string
	BackupFile string
	Service    *PortRedirectService
	Logger     *log.Logger
}

// NewIntegrationEnvironment creates a new integration test environment
func NewIntegrationEnvironment(t *testing.T) *TestIntegrationEnvironment {
	tempDir, err := os.MkdirTemp("", "port-redirect-integration-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	env := &TestIntegrationEnvironment{
		TempDir:    tempDir,
		ConfigFile: filepath.Join(tempDir, "config.txt"),
		HostsFile:  filepath.Join(tempDir, "hosts"),
		BackupFile: filepath.Join(tempDir, "hosts.backup"),
		Logger:     log.New(io.Discard, "", 0), // Discard logs during testing
	}

	// Create initial hosts file
	initialHosts := `127.0.0.1	localhost
::1		localhost
`
	if err := os.WriteFile(env.HostsFile, []byte(initialHosts), 0644); err != nil {
		t.Fatalf("Failed to create initial hosts file: %v", err)
	}

	// Create initial config file
	initialConfig := `# Test configuration
3000
8080
5173
`
	if err := os.WriteFile(env.ConfigFile, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to create initial config file: %v", err)
	}

	return env
}

// CreateService creates a service instance for testing
func (env *TestIntegrationEnvironment) CreateService() {
	config := &Config{
		Ports:           []int{3000, 8080, 5173},
		ConfigFilePath:  env.ConfigFile,
		HostsBackupPath: env.BackupFile,
		LogLevel:        "INFO",
	}

	env.Service = NewPortRedirectService(config, env.Logger, nil)
	// Override hosts manager to use test files
	env.Service.hostsManager = NewHostsManager(env.HostsFile, env.BackupFile)
}

// Cleanup removes the integration test environment
func (env *TestIntegrationEnvironment) Cleanup() {
	if env.Service != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		env.Service.Stop(ctx)
		env.Service.Cleanup()
	}
	os.RemoveAll(env.TempDir)
}

// TestEndToEndRedirectFlow tests the complete redirect flow
func TestEndToEndRedirectFlow(t *testing.T) {
	env := NewIntegrationEnvironment(t)
	defer env.Cleanup()

	env.CreateService()

	// Setup hosts file entries
	err := env.Service.hostsManager.CreateBackup()
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	err = env.Service.hostsManager.AddPortEntries(env.Service.config.Ports)
	if err != nil {
		t.Fatalf("Failed to add port entries: %v", err)
	}

	// Test cases for different scenarios
	testCases := []struct {
		name           string
		host           string
		expectedStatus int
		expectedTarget string
	}{
		{
			name:           "valid configured port",
			host:           "3000.local",
			expectedStatus: http.StatusMovedPermanently,
			expectedTarget: "http://localhost:3000",
		},
		{
			name:           "another valid port",
			host:           "8080.dev",
			expectedStatus: http.StatusMovedPermanently,
			expectedTarget: "http://localhost:8080",
		},
		{
			name:           "third valid port",
			host:           "5173.test",
			expectedStatus: http.StatusMovedPermanently,
			expectedTarget: "http://localhost:5173",
		},
		{
			name:           "unconfigured port",
			host:           "9000.local",
			expectedStatus: http.StatusNotFound,
			expectedTarget: "",
		},
		{
			name:           "invalid host format",
			host:           "invalid.local",
			expectedStatus: http.StatusNotFound,
			expectedTarget: "",
		},
		{
			name:           "invalid port range",
			host:           "99999.local",
			expectedStatus: http.StatusBadRequest,
			expectedTarget: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create HTTP request
			req, err := http.NewRequest("GET", "http://"+tc.host+"/", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Host = tc.host

			// Create response recorder
			recorder := &ResponseRecorder{
				StatusCode: 200,
				Headers:    make(http.Header),
				Body:       make([]byte, 0),
			}

			// Handle the request
			env.Service.handleRedirect(recorder, req)

			// Verify status code
			if recorder.StatusCode != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, recorder.StatusCode)
			}

			// Verify redirect location if expected
			if tc.expectedTarget != "" {
				location := recorder.Headers.Get("Location")
				if location != tc.expectedTarget {
					t.Errorf("Expected location %s, got %s", tc.expectedTarget, location)
				}
			}
		})
	}
}

// ResponseRecorder is a simple HTTP response recorder for testing
type ResponseRecorder struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

func (r *ResponseRecorder) Header() http.Header {
	return r.Headers
}

func (r *ResponseRecorder) Write(data []byte) (int, error) {
	r.Body = append(r.Body, data...)
	return len(data), nil
}

func (r *ResponseRecorder) WriteHeader(statusCode int) {
	r.StatusCode = statusCode
}

// TestConfigurationReload tests dynamic configuration reloading
func TestConfigurationReload(t *testing.T) {
	env := NewIntegrationEnvironment(t)
	defer env.Cleanup()

	env.CreateService()

	// Setup initial hosts file
	err := env.Service.hostsManager.CreateBackup()
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	err = env.Service.hostsManager.AddPortEntries(env.Service.config.Ports)
	if err != nil {
		t.Fatalf("Failed to add initial port entries: %v", err)
	}

	// Verify initial configuration
	initialPorts := env.Service.config.Ports
	if len(initialPorts) != 3 {
		t.Fatalf("Expected 3 initial ports, got %d", len(initialPorts))
	}

	// Create config watcher
	env.Service.configWatcher = NewConfigWatcher(env.ConfigFile, env.Logger)
	err = env.Service.configWatcher.Start()
	if err != nil {
		t.Fatalf("Failed to start config watcher: %v", err)
	}

	// Start handling config reloads in background
	go func() {
		for {
			select {
			case newPorts := <-env.Service.configWatcher.ReloadChan():
				// Validate the new configuration
				if err := validateConfigUpdate(newPorts); err != nil {
					env.Service.structuredLogger.LogError("config_validation", "Invalid configuration update", err)
					continue
				}

				// Update the service configuration
				env.Service.config.Ports = newPorts
				env.Service.configLoaded = time.Now()

				// Update hosts file entries
				if err := env.Service.hostsManager.UpdatePortEntries(newPorts); err != nil {
					env.Service.structuredLogger.LogError("config_hosts_update", "Failed to update hosts file entries", err)
				}

			case err := <-env.Service.configWatcher.ErrorChan():
				env.Service.structuredLogger.LogError("config_watcher", "Configuration watcher error", err)
			}
		}
	}()

	// Update configuration file
	newConfig := `# Updated configuration
9000
9001
3000
`
	err = os.WriteFile(env.ConfigFile, []byte(newConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to update config file: %v", err)
	}

	// Wait for configuration reload (with timeout)
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	configReloaded := false
	for !configReloaded {
		select {
		case <-timeout:
			t.Fatalf("Configuration reload timed out")
		case <-ticker.C:
			// Check if configuration has been updated
			currentPorts := env.Service.config.Ports
			if len(currentPorts) == 3 && containsPort(currentPorts, 9000) && containsPort(currentPorts, 9001) {
				configReloaded = true
			}
		}
	}

	// Verify new configuration is loaded
	newPorts := env.Service.config.Ports
	if len(newPorts) != 3 {
		t.Errorf("Expected 3 ports after reload, got %d", len(newPorts))
	}

	expectedPorts := []int{9000, 9001, 3000}
	for _, expectedPort := range expectedPorts {
		if !containsPort(newPorts, expectedPort) {
			t.Errorf("Expected port %d not found in reloaded config", expectedPort)
		}
	}

	// Verify hosts file has been updated
	isValid, missing, extra := env.Service.hostsManager.ValidateEntries(newPorts)
	if !isValid {
		t.Errorf("Hosts file should be valid after config reload")
		if len(missing) > 0 {
			t.Errorf("Missing entries: %v", missing)
		}
		if len(extra) > 0 {
			t.Errorf("Extra entries: %v", extra)
		}
	}

	// Verify old entries are removed
	hostsContent, err := os.ReadFile(env.HostsFile)
	if err != nil {
		t.Fatalf("Failed to read hosts file: %v", err)
	}

	hostsStr := string(hostsContent)
	if strings.Contains(hostsStr, "8080.local") {
		t.Errorf("Old port 8080 entries should be removed")
	}
	if strings.Contains(hostsStr, "5173.local") {
		t.Errorf("Old port 5173 entries should be removed")
	}

	// Verify new entries are added
	if !strings.Contains(hostsStr, "9000.local") {
		t.Errorf("New port 9000 entries should be added")
	}
	if !strings.Contains(hostsStr, "9001.local") {
		t.Errorf("New port 9001 entries should be added")
	}
}

// containsPort checks if a port is in the ports slice
func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// TestServiceLifecycle tests service startup and shutdown
func TestServiceLifecycle(t *testing.T) {
	env := NewIntegrationEnvironment(t)
	defer env.Cleanup()

	env.CreateService()

	// Test service initialization
	if env.Service.startTime.IsZero() {
		t.Errorf("Service start time should be set")
	}

	if env.Service.configLoaded.IsZero() {
		t.Errorf("Config loaded time should be set")
	}

	// Test hosts file backup creation
	err := env.Service.hostsManager.CreateBackup()
	if err != nil {
		t.Errorf("Failed to create hosts backup: %v", err)
	}

	if !env.Service.hostsManager.BackupExists() {
		t.Errorf("Backup should exist after creation")
	}

	// Test hosts file setup
	err = env.Service.hostsManager.AddPortEntries(env.Service.config.Ports)
	if err != nil {
		t.Errorf("Failed to add port entries: %v", err)
	}

	// Verify hosts file entries
	isValid, missing, extra := env.Service.hostsManager.ValidateEntries(env.Service.config.Ports)
	if !isValid {
		t.Errorf("Hosts file should be valid after setup")
		if len(missing) > 0 {
			t.Errorf("Missing entries: %v", missing)
		}
		if len(extra) > 0 {
			t.Errorf("Extra entries: %v", extra)
		}
	}

	// Test service status collection
	status := env.Service.GetServiceStatus()
	if status == nil {
		t.Errorf("Service status should not be nil")
		return
	}

	if status.Uptime <= 0 {
		t.Errorf("Service uptime should be positive")
	}

	if len(status.PortsConfigured) != len(env.Service.config.Ports) {
		t.Errorf("Status should reflect configured ports")
	}

	// Test graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = env.Service.Stop(ctx)
	if err != nil {
		t.Errorf("Service should stop gracefully: %v", err)
	}

	// Test cleanup
	err = env.Service.Cleanup()
	if err != nil {
		t.Errorf("Service cleanup should succeed: %v", err)
	}

	// Verify hosts file is cleaned up
	hostsContent, err := os.ReadFile(env.HostsFile)
	if err != nil {
		t.Fatalf("Failed to read hosts file after cleanup: %v", err)
	}

	hostsStr := string(hostsContent)
	if strings.Contains(hostsStr, "# BEGIN PORT-REDIRECT-SERVICE") {
		t.Errorf("Managed section should be removed after cleanup")
	}

	// Verify backup still exists (should not be removed during cleanup)
	if !env.Service.hostsManager.BackupExists() {
		t.Errorf("Backup should still exist after cleanup")
	}
}

// TestHostsFileManagement tests comprehensive hosts file management
func TestHostsFileManagement(t *testing.T) {
	env := NewIntegrationEnvironment(t)
	defer env.Cleanup()

	env.CreateService()

	// Test backup creation
	err := env.Service.hostsManager.CreateBackup()
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Read original hosts content
	originalContent, err := os.ReadFile(env.HostsFile)
	if err != nil {
		t.Fatalf("Failed to read original hosts file: %v", err)
	}

	// Test adding entries for multiple ports
	testPorts := []int{3000, 8080, 5173, 9000}
	err = env.Service.hostsManager.AddPortEntries(testPorts)
	if err != nil {
		t.Fatalf("Failed to add port entries: %v", err)
	}

	// Verify all expected entries are present
	hostsContent, err := os.ReadFile(env.HostsFile)
	if err != nil {
		t.Fatalf("Failed to read hosts file: %v", err)
	}

	hostsStr := string(hostsContent)

	// Check for managed section markers
	if !strings.Contains(hostsStr, "# BEGIN PORT-REDIRECT-SERVICE") {
		t.Errorf("Missing begin marker")
	}
	if !strings.Contains(hostsStr, "# END PORT-REDIRECT-SERVICE") {
		t.Errorf("Missing end marker")
	}

	// Check for all port entries across all TLDs
	tlds := []string{"local", "dev", "test", "localhost"}
	for _, port := range testPorts {
		for _, tld := range tlds {
			expectedEntry := fmt.Sprintf("%d.%s 127.0.0.1", port, tld)
			if !strings.Contains(hostsStr, expectedEntry) {
				t.Errorf("Missing expected entry: %s", expectedEntry)
			}
		}
	}

	// Test validation
	isValid, missing, extra := env.Service.hostsManager.ValidateEntries(testPorts)
	if !isValid {
		t.Errorf("Entries should be valid")
		if len(missing) > 0 {
			t.Errorf("Unexpected missing entries: %v", missing)
		}
		if len(extra) > 0 {
			t.Errorf("Unexpected extra entries: %v", extra)
		}
	}

	// Test updating to different ports
	newPorts := []int{4000, 4001}
	err = env.Service.hostsManager.UpdatePortEntries(newPorts)
	if err != nil {
		t.Fatalf("Failed to update port entries: %v", err)
	}

	// Verify old entries are removed and new ones added
	updatedContent, err := os.ReadFile(env.HostsFile)
	if err != nil {
		t.Fatalf("Failed to read updated hosts file: %v", err)
	}

	updatedStr := string(updatedContent)

	// Old entries should be gone
	if strings.Contains(updatedStr, "3000.local") {
		t.Errorf("Old entries should be removed")
	}

	// New entries should be present
	if !strings.Contains(updatedStr, "4000.local 127.0.0.1") {
		t.Errorf("New entries should be added")
	}
	if !strings.Contains(updatedStr, "4001.local 127.0.0.1") {
		t.Errorf("New entries should be added")
	}

	// Test complete removal
	err = env.Service.hostsManager.RemovePortEntries()
	if err != nil {
		t.Fatalf("Failed to remove port entries: %v", err)
	}

	// Verify managed section is completely removed
	cleanedContent, err := os.ReadFile(env.HostsFile)
	if err != nil {
		t.Fatalf("Failed to read cleaned hosts file: %v", err)
	}

	cleanedStr := string(cleanedContent)
	if strings.Contains(cleanedStr, "# BEGIN PORT-REDIRECT-SERVICE") {
		t.Errorf("Managed section should be completely removed")
	}
	if strings.Contains(cleanedStr, "4000.local") {
		t.Errorf("All port entries should be removed")
	}

	// Test backup restoration
	err = env.Service.hostsManager.RestoreBackup()
	if err != nil {
		t.Fatalf("Failed to restore backup: %v", err)
	}

	// Verify content matches original
	restoredContent, err := os.ReadFile(env.HostsFile)
	if err != nil {
		t.Fatalf("Failed to read restored hosts file: %v", err)
	}

	if string(restoredContent) != string(originalContent) {
		t.Errorf("Restored content should match original")
	}
}

// TestErrorHandling tests various error conditions
func TestErrorHandling(t *testing.T) {
	env := NewIntegrationEnvironment(t)
	defer env.Cleanup()

	env.CreateService()

	t.Run("invalid config file", func(t *testing.T) {
		// Create invalid config file
		invalidConfig := "3000\ninvalid_port\n8080\n"
		err := os.WriteFile(env.ConfigFile, []byte(invalidConfig), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid config: %v", err)
		}

		// Try to parse invalid config
		_, err = parseConfigFile(env.ConfigFile)
		if err == nil {
			t.Errorf("Should fail to parse invalid config")
		}
	})

	t.Run("missing config file", func(t *testing.T) {
		missingFile := filepath.Join(env.TempDir, "missing.txt")
		_, err := parseConfigFile(missingFile)
		if err == nil {
			t.Errorf("Should fail to parse missing config file")
		}
	})

	t.Run("readonly hosts file", func(t *testing.T) {
		// Make hosts file readonly
		err := os.Chmod(env.HostsFile, 0444)
		if err != nil {
			t.Fatalf("Failed to make hosts file readonly: %v", err)
		}

		// Try to add entries (should fail gracefully)
		err = env.Service.hostsManager.AddPortEntries([]int{3000})
		if err == nil {
			t.Errorf("Should fail to write to readonly hosts file")
		}

		// Restore write permissions for cleanup
		os.Chmod(env.HostsFile, 0644)
	})

	t.Run("configuration validation errors", func(t *testing.T) {
		// Test empty configuration
		env.Service.config.Ports = []int{}
		errors := env.Service.ValidateConfiguration()
		if len(errors) == 0 {
			t.Errorf("Should detect empty configuration error")
		}

		// Test duplicate ports
		env.Service.config.Ports = []int{3000, 3000}
		errors = env.Service.ValidateConfiguration()
		if len(errors) == 0 {
			t.Errorf("Should detect duplicate ports error")
		}

		// Test invalid port range
		env.Service.config.Ports = []int{0, 65536}
		errors = env.Service.ValidateConfiguration()
		if len(errors) == 0 {
			t.Errorf("Should detect invalid port range errors")
		}
	})
}

// TestConcurrentOperations tests concurrent access to service components
func TestConcurrentOperations(t *testing.T) {
	env := NewIntegrationEnvironment(t)
	defer env.Cleanup()

	env.CreateService()

	// Setup initial state
	err := env.Service.hostsManager.CreateBackup()
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	err = env.Service.hostsManager.AddPortEntries(env.Service.config.Ports)
	if err != nil {
		t.Fatalf("Failed to add initial entries: %v", err)
	}

	// Test concurrent status requests
	t.Run("concurrent status requests", func(t *testing.T) {
		done := make(chan bool, 10)

		// Launch multiple goroutines making status requests
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- true }()

				status := env.Service.GetServiceStatus()
				if status == nil {
					t.Errorf("Status should not be nil")
					return
				}

				config := env.Service.GetServiceConfig()
				if config == nil {
					t.Errorf("Config should not be nil")
					return
				}

				errors := env.Service.ValidateConfiguration()
				_ = errors // Just ensure it doesn't panic
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	// Test concurrent redirect handling
	t.Run("concurrent redirect handling", func(t *testing.T) {
		done := make(chan bool, 10)

		// Launch multiple goroutines handling redirects
		for i := 0; i < 10; i++ {
			go func(index int) {
				defer func() { done <- true }()

				host := fmt.Sprintf("300%d.local", index%3) // Rotate through 3000, 3001, 3002
				req, err := http.NewRequest("GET", "http://"+host+"/", nil)
				if err != nil {
					t.Errorf("Failed to create request: %v", err)
					return
				}
				req.Host = host

				recorder := &ResponseRecorder{
					StatusCode: 200,
					Headers:    make(http.Header),
					Body:       make([]byte, 0),
				}

				env.Service.handleRedirect(recorder, req)
				// Just ensure it doesn't panic or deadlock
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}
