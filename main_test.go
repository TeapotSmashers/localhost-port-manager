package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEnvironment provides a test environment with temporary files
type TestEnvironment struct {
	TempDir        string
	MockHostsFile  string
	MockConfigFile string
	TestServer     *httptest.Server
}

// NewTestEnvironment creates a new test environment
func NewTestEnvironment(t *testing.T) *TestEnvironment {
	tempDir, err := os.MkdirTemp("", "port-redirect-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	env := &TestEnvironment{
		TempDir:        tempDir,
		MockHostsFile:  filepath.Join(tempDir, "hosts"),
		MockConfigFile: filepath.Join(tempDir, "config.txt"),
	}

	// Create initial mock hosts file
	initialHosts := `127.0.0.1	localhost
::1		localhost
`
	if err := os.WriteFile(env.MockHostsFile, []byte(initialHosts), 0644); err != nil {
		t.Fatalf("Failed to create mock hosts file: %v", err)
	}

	return env
}

// Cleanup removes the test environment
func (env *TestEnvironment) Cleanup() {
	if env.TestServer != nil {
		env.TestServer.Close()
	}
	os.RemoveAll(env.TempDir)
}

// TestParseConfigFile tests configuration file parsing
func TestParseConfigFile(t *testing.T) {
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	tests := []struct {
		name        string
		content     string
		expected    []int
		expectError bool
	}{
		{
			name:     "valid config with comments",
			content:  "# Port configuration\n3000\n8080\n# Another comment\n5173\n",
			expected: []int{3000, 8080, 5173},
		},
		{
			name:     "valid config with empty lines",
			content:  "3000\n\n8080\n\n5173\n",
			expected: []int{3000, 8080, 5173},
		},
		{
			name:        "invalid port number",
			content:     "3000\ninvalid\n8080\n",
			expectError: true,
		},
		{
			name:        "port out of range - too low",
			content:     "0\n8080\n",
			expectError: true,
		},
		{
			name:        "port out of range - too high",
			content:     "65536\n8080\n",
			expectError: true,
		},
		{
			name:     "only comments and empty lines",
			content:  "# Comment only\n\n# Another comment\n",
			expected: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write test config file
			if err := os.WriteFile(env.MockConfigFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to write test config: %v", err)
			}

			ports, err := parseConfigFile(env.MockConfigFile)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(ports) != len(tt.expected) {
				t.Errorf("Expected %d ports, got %d", len(tt.expected), len(ports))
				return
			}

			for i, expected := range tt.expected {
				if ports[i] != expected {
					t.Errorf("Expected port %d at index %d, got %d", expected, i, ports[i])
				}
			}
		})
	}
}

// TestCreateDefaultConfig tests default configuration creation
func TestCreateDefaultConfig(t *testing.T) {
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	configPath := filepath.Join(env.TempDir, "new-config.txt")

	// Test creating new config
	err := createDefaultConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to create default config: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("Default config file was not created")
	}

	// Verify content contains default ports
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read created config: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "3000") {
		t.Errorf("Default config should contain port 3000")
	}
	if !strings.Contains(contentStr, "8080") {
		t.Errorf("Default config should contain port 8080")
	}
	if !strings.Contains(contentStr, "5173") {
		t.Errorf("Default config should contain port 5173")
	}

	// Test that existing config is not overwritten
	customContent := "9000\n9001\n"
	if err := os.WriteFile(configPath, []byte(customContent), 0644); err != nil {
		t.Fatalf("Failed to write custom config: %v", err)
	}

	err = createDefaultConfig(configPath)
	if err != nil {
		t.Errorf("createDefaultConfig should not error on existing file: %v", err)
	}

	// Verify original content is preserved
	newContent, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config after second create: %v", err)
	}

	if string(newContent) != customContent {
		t.Errorf("Existing config was overwritten")
	}
}

// TestExtractPortFromHost tests port extraction from host headers
func TestExtractPortFromHost(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		expectedPort int
		expectedOk   bool
	}{
		{
			name:         "valid local domain",
			host:         "3000.local",
			expectedPort: 3000,
			expectedOk:   true,
		},
		{
			name:         "valid dev domain",
			host:         "8080.dev",
			expectedPort: 8080,
			expectedOk:   true,
		},
		{
			name:         "valid test domain",
			host:         "5173.test",
			expectedPort: 5173,
			expectedOk:   true,
		},
		{
			name:         "valid localhost domain",
			host:         "9000.localhost",
			expectedPort: 9000,
			expectedOk:   true,
		},
		{
			name:         "valid ai domain",
			host:         "3000.ai",
			expectedPort: 3000,
			expectedOk:   true,
		},
		{
			name:         "host with port suffix",
			host:         "3000.local:8080",
			expectedPort: 3000,
			expectedOk:   true,
		},
		{
			name:       "invalid format - no port",
			host:       "example.local",
			expectedOk: false,
		},
		{
			name:       "invalid format - no tld",
			host:       "3000",
			expectedOk: false,
		},
		{
			name:       "invalid format - wrong tld",
			host:       "3000.invalid",
			expectedOk: false,
		},
		{
			name:       "empty host",
			host:       "",
			expectedOk: false,
		},
		{
			name:         "large port number",
			host:         "65535.local",
			expectedPort: 65535,
			expectedOk:   true,
		},
		{
			name:         "single digit port",
			host:         "1.local",
			expectedPort: 1,
			expectedOk:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, ok := extractPortFromHost(tt.host)

			if ok != tt.expectedOk {
				t.Errorf("Expected ok=%v, got ok=%v", tt.expectedOk, ok)
			}

			if tt.expectedOk && port != tt.expectedPort {
				t.Errorf("Expected port=%d, got port=%d", tt.expectedPort, port)
			}
		})
	}
}

// TestValidatePort tests port number validation
func TestValidatePort(t *testing.T) {
	tests := []struct {
		name     string
		port     int
		expected bool
	}{
		{"valid port 1", 1, true},
		{"valid port 80", 80, true},
		{"valid port 3000", 3000, true},
		{"valid port 65535", 65535, true},
		{"invalid port 0", 0, false},
		{"invalid port -1", -1, false},
		{"invalid port 65536", 65536, false},
		{"invalid port 100000", 100000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validatePort(tt.port)
			if result != tt.expected {
				t.Errorf("validatePort(%d) = %v, expected %v", tt.port, result, tt.expected)
			}
		})
	}
}

// TestIsPortConfigured tests port configuration checking
func TestIsPortConfigured(t *testing.T) {
	configuredPorts := []int{3000, 8080, 5173}

	tests := []struct {
		name     string
		port     int
		expected bool
	}{
		{"configured port 3000", 3000, true},
		{"configured port 8080", 8080, true},
		{"configured port 5173", 5173, true},
		{"unconfigured port 9000", 9000, false},
		{"unconfigured port 80", 80, false},
		{"unconfigured port 443", 443, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPortConfigured(tt.port, configuredPorts)
			if result != tt.expected {
				t.Errorf("isPortConfigured(%d) = %v, expected %v", tt.port, result, tt.expected)
			}
		})
	}
}

// TestValidateConfigUpdate tests configuration update validation
func TestValidateConfigUpdate(t *testing.T) {
	tests := []struct {
		name        string
		ports       []int
		expectError bool
	}{
		{
			name:  "valid config",
			ports: []int{3000, 8080, 5173},
		},
		{
			name:        "empty config",
			ports:       []int{},
			expectError: true,
		},
		{
			name:        "duplicate ports",
			ports:       []int{3000, 8080, 3000},
			expectError: true,
		},
		{
			name:  "single port",
			ports: []int{3000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfigUpdate(tt.ports)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestHostsManager tests hosts file management functionality
func TestHostsManager(t *testing.T) {
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	backupPath := filepath.Join(env.TempDir, "hosts.backup")
	hm := NewHostsManager(env.MockHostsFile, backupPath)

	t.Run("CreateBackup", func(t *testing.T) {
		err := hm.CreateBackup()
		if err != nil {
			t.Errorf("Failed to create backup: %v", err)
		}

		// Verify backup file exists
		if !hm.BackupExists() {
			t.Errorf("Backup file should exist")
		}

		// Verify backup content matches original
		originalContent, err := os.ReadFile(env.MockHostsFile)
		if err != nil {
			t.Fatalf("Failed to read original hosts file: %v", err)
		}

		backupContent, err := os.ReadFile(backupPath)
		if err != nil {
			t.Fatalf("Failed to read backup file: %v", err)
		}

		if string(originalContent) != string(backupContent) {
			t.Errorf("Backup content doesn't match original")
		}
	})

	t.Run("AddPortEntries", func(t *testing.T) {
		ports := []int{3000, 8080}
		err := hm.AddPortEntries(ports)
		if err != nil {
			t.Errorf("Failed to add port entries: %v", err)
		}

		// Read hosts file and verify entries were added
		content, err := os.ReadFile(env.MockHostsFile)
		if err != nil {
			t.Fatalf("Failed to read hosts file: %v", err)
		}

		contentStr := string(content)

		// Check for managed section markers
		if !strings.Contains(contentStr, "# BEGIN PORT-REDIRECT-SERVICE") {
			t.Errorf("Missing begin marker")
		}
		if !strings.Contains(contentStr, "# END PORT-REDIRECT-SERVICE") {
			t.Errorf("Missing end marker")
		}

		// Check for specific entries
		expectedEntries := []string{
			"3000.local 127.0.0.1",
			"3000.dev 127.0.0.1",
			"3000.test 127.0.0.1",
			"3000.localhost 127.0.0.1",
			"8080.local 127.0.0.1",
			"8080.dev 127.0.0.1",
			"8080.test 127.0.0.1",
			"8080.localhost 127.0.0.1",
		}

		for _, entry := range expectedEntries {
			if !strings.Contains(contentStr, entry) {
				t.Errorf("Missing expected entry: %s", entry)
			}
		}
	})

	t.Run("ValidateEntries", func(t *testing.T) {
		ports := []int{3000, 8080}

		// Entries should be valid after adding them
		isValid, missing, extra := hm.ValidateEntries(ports)
		if !isValid {
			t.Errorf("Entries should be valid")
		}
		if len(missing) > 0 {
			t.Errorf("Should have no missing entries, got: %v", missing)
		}
		if len(extra) > 0 {
			t.Errorf("Should have no extra entries, got: %v", extra)
		}

		// Test with different ports (should show missing entries)
		differentPorts := []int{9000, 9001}
		isValid, missing, extra = hm.ValidateEntries(differentPorts)
		if isValid {
			t.Errorf("Entries should not be valid for different ports")
		}
		if len(missing) == 0 {
			t.Errorf("Should have missing entries")
		}
		if len(extra) == 0 {
			t.Errorf("Should have extra entries")
		}
	})

	t.Run("UpdatePortEntries", func(t *testing.T) {
		// Update to different ports
		newPorts := []int{5173, 9000}
		err := hm.UpdatePortEntries(newPorts)
		if err != nil {
			t.Errorf("Failed to update port entries: %v", err)
		}

		// Validate new entries
		isValid, missing, extra := hm.ValidateEntries(newPorts)
		if !isValid {
			t.Errorf("Updated entries should be valid")
		}
		if len(missing) > 0 {
			t.Errorf("Should have no missing entries after update, got: %v", missing)
		}
		if len(extra) > 0 {
			t.Errorf("Should have no extra entries after update, got: %v", extra)
		}

		// Verify old entries are gone
		content, err := os.ReadFile(env.MockHostsFile)
		if err != nil {
			t.Fatalf("Failed to read hosts file: %v", err)
		}

		contentStr := string(content)
		if strings.Contains(contentStr, "3000.local") {
			t.Errorf("Old entries should be removed")
		}
		if strings.Contains(contentStr, "8080.local") {
			t.Errorf("Old entries should be removed")
		}
	})

	t.Run("RemovePortEntries", func(t *testing.T) {
		err := hm.RemovePortEntries()
		if err != nil {
			t.Errorf("Failed to remove port entries: %v", err)
		}

		// Verify managed section is removed
		content, err := os.ReadFile(env.MockHostsFile)
		if err != nil {
			t.Fatalf("Failed to read hosts file: %v", err)
		}

		contentStr := string(content)
		if strings.Contains(contentStr, "# BEGIN PORT-REDIRECT-SERVICE") {
			t.Errorf("Managed section should be removed")
		}
		if strings.Contains(contentStr, "5173.local") {
			t.Errorf("Port entries should be removed")
		}
	})

	t.Run("RestoreBackup", func(t *testing.T) {
		// Modify hosts file
		modifiedContent := "127.0.0.1 localhost\n# Modified content\n"
		err := os.WriteFile(env.MockHostsFile, []byte(modifiedContent), 0644)
		if err != nil {
			t.Fatalf("Failed to modify hosts file: %v", err)
		}

		// Restore from backup
		err = hm.RestoreBackup()
		if err != nil {
			t.Errorf("Failed to restore backup: %v", err)
		}

		// Verify content is restored
		restoredContent, err := os.ReadFile(env.MockHostsFile)
		if err != nil {
			t.Fatalf("Failed to read restored hosts file: %v", err)
		}

		backupContent, err := os.ReadFile(backupPath)
		if err != nil {
			t.Fatalf("Failed to read backup file: %v", err)
		}

		if string(restoredContent) != string(backupContent) {
			t.Errorf("Restored content doesn't match backup")
		}
	})
}

// TestHTTPHandlers tests HTTP request handlers using httptest
func TestHTTPHandlers(t *testing.T) {
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	// Create a test service
	logger := log.New(io.Discard, "", 0) // Discard logs during testing
	config := &Config{
		Ports:           []int{3000, 8080, 5173},
		ConfigFilePath:  env.MockConfigFile,
		HostsBackupPath: filepath.Join(env.TempDir, "hosts.backup"),
	}

	service := NewPortRedirectService(config, logger, nil)

	t.Run("handleRedirect - valid port", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://3000.local/", nil)
		req.Host = "3000.local"
		w := httptest.NewRecorder()

		service.handleRedirect(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusMovedPermanently {
			t.Errorf("Expected status %d, got %d", http.StatusMovedPermanently, resp.StatusCode)
		}

		location := resp.Header.Get("Location")
		expectedLocation := "http://localhost:3000"
		if location != expectedLocation {
			t.Errorf("Expected location %s, got %s", expectedLocation, location)
		}
	})

	t.Run("handleRedirect - invalid host format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://invalid.local/", nil)
		req.Host = "invalid.local"
		w := httptest.NewRecorder()

		service.handleRedirect(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, resp.StatusCode)
		}
	})

	t.Run("handleRedirect - invalid port range", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://99999.local/", nil)
		req.Host = "99999.local"
		w := httptest.NewRecorder()

		service.handleRedirect(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
		}
	})

	t.Run("handleRedirect - unconfigured port", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://9000.local/", nil)
		req.Host = "9000.local"
		w := httptest.NewRecorder()

		service.handleRedirect(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, resp.StatusCode)
		}
	})

	t.Run("handleStatus - HTML", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/status", nil)
		w := httptest.NewRecorder()

		service.handleStatus(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(contentType, "text/html") {
			t.Errorf("Expected HTML content type, got %s", contentType)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Port Redirect Service Status") {
			t.Errorf("Response should contain status page title")
		}
		if !strings.Contains(bodyStr, "3000") {
			t.Errorf("Response should contain configured port 3000")
		}
	})

	t.Run("handleStatus - JSON", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/status?format=json", nil)
		w := httptest.NewRecorder()

		service.handleStatus(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			t.Errorf("Expected JSON content type, got %s", contentType)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, "status") {
			t.Errorf("JSON response should contain status field")
		}
		if !strings.Contains(bodyStr, "config") {
			t.Errorf("JSON response should contain config field")
		}
	})
}

// TestGetClientIP tests client IP extraction
func TestGetClientIP(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	config := &Config{Ports: []int{3000}}
	service := NewPortRedirectService(config, logger, nil)

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{
			name:       "direct connection",
			remoteAddr: "192.168.1.100:12345",
			expected:   "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For header",
			remoteAddr: "127.0.0.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 192.168.1.100"},
			expected:   "203.0.113.1",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "127.0.0.1:12345",
			headers:    map[string]string{"X-Real-IP": "203.0.113.2"},
			expected:   "203.0.113.2",
		},
		{
			name:       "X-Forwarded-For takes precedence",
			remoteAddr: "127.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
				"X-Real-IP":       "203.0.113.2",
			},
			expected: "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			clientIP := service.getClientIP(req)
			if clientIP != tt.expected {
				t.Errorf("Expected client IP %s, got %s", tt.expected, clientIP)
			}
		})
	}
}

// TestStructuredLogger tests structured logging functionality
func TestStructuredLogger(t *testing.T) {
	var logOutput strings.Builder
	logger := log.New(&logOutput, "", 0)
	structuredLogger := NewStructuredLogger(logger)

	t.Run("LogRedirect", func(t *testing.T) {
		logOutput.Reset()
		structuredLogger.LogRedirect("3000.local", "http://localhost:3000", "192.168.1.100", 301)

		output := logOutput.String()
		if !strings.Contains(output, "[REDIRECT]") {
			t.Errorf("Log should contain [REDIRECT] tag")
		}
		if !strings.Contains(output, "source=3000.local") {
			t.Errorf("Log should contain source host")
		}
		if !strings.Contains(output, "target=http://localhost:3000") {
			t.Errorf("Log should contain target URL")
		}
		if !strings.Contains(output, "client=192.168.1.100") {
			t.Errorf("Log should contain client IP")
		}
		if !strings.Contains(output, "status=301") {
			t.Errorf("Log should contain status code")
		}
	})

	t.Run("LogError", func(t *testing.T) {
		logOutput.Reset()
		testErr := fmt.Errorf("test error")
		structuredLogger.LogError("test_operation", "test message", testErr)

		output := logOutput.String()
		if !strings.Contains(output, "[ERROR]") {
			t.Errorf("Log should contain [ERROR] tag")
		}
		if !strings.Contains(output, "operation=test_operation") {
			t.Errorf("Log should contain operation")
		}
		if !strings.Contains(output, "message=test message") {
			t.Errorf("Log should contain message")
		}
		if !strings.Contains(output, "error=test error") {
			t.Errorf("Log should contain error")
		}
	})

	t.Run("LogInfo", func(t *testing.T) {
		logOutput.Reset()
		structuredLogger.LogInfo("test_operation", "test message")

		output := logOutput.String()
		if !strings.Contains(output, "[INFO]") {
			t.Errorf("Log should contain [INFO] tag")
		}
		if !strings.Contains(output, "operation=test_operation") {
			t.Errorf("Log should contain operation")
		}
		if !strings.Contains(output, "message=test message") {
			t.Errorf("Log should contain message")
		}
	})

	t.Run("LogStartup", func(t *testing.T) {
		logOutput.Reset()
		structuredLogger.LogStartup("1.0.0", "/etc/config.txt", 3)

		output := logOutput.String()
		if !strings.Contains(output, "[STARTUP]") {
			t.Errorf("Log should contain [STARTUP] tag")
		}
		if !strings.Contains(output, "version=1.0.0") {
			t.Errorf("Log should contain version")
		}
		if !strings.Contains(output, "config=/etc/config.txt") {
			t.Errorf("Log should contain config path")
		}
		if !strings.Contains(output, "ports=3") {
			t.Errorf("Log should contain port count")
		}
	})
}

// TestPortExtractionRegex tests the regex pattern directly
func TestPortExtractionRegex(t *testing.T) {
	// Test the actual regex pattern used in the code
	pattern := `^(\d+)\.(local|dev|test|localhost|ai|com|net|org)$`
	regex := regexp.MustCompile(pattern)

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid local", "3000.local", true},
		{"valid dev", "8080.dev", true},
		{"valid test", "5173.test", true},
		{"valid localhost", "9000.localhost", true},
		{"valid ai", "3000.ai", true},
		{"valid com", "8080.com", true},
		{"invalid tld", "3000.invalid", false},
		{"no port", "example.local", false},
		{"no tld", "3000", false},
		{"extra characters", "3000.local.extra", false},
		{"leading characters", "prefix3000.local", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := regex.MatchString(tt.input)
			if matches != tt.expected {
				t.Errorf("Pattern match for %s: expected %v, got %v", tt.input, tt.expected, matches)
			}
		})
	}
}

// TestServiceStatus tests service status collection
func TestServiceStatus(t *testing.T) {
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	logger := log.New(io.Discard, "", 0)
	config := &Config{
		Ports:           []int{3000, 8080},
		ConfigFilePath:  env.MockConfigFile,
		HostsBackupPath: filepath.Join(env.TempDir, "hosts.backup"),
	}

	service := NewPortRedirectService(config, logger, nil)

	// Override hosts manager to use test files
	service.hostsManager = NewHostsManager(env.MockHostsFile, config.HostsBackupPath)

	t.Run("GetServiceStatus", func(t *testing.T) {
		status := service.GetServiceStatus()

		if status == nil {
			t.Fatalf("Status should not be nil")
		}

		if len(status.PortsConfigured) != 2 {
			t.Errorf("Expected 2 configured ports, got %d", len(status.PortsConfigured))
		}

		if status.PortsConfigured[0] != 3000 || status.PortsConfigured[1] != 8080 {
			t.Errorf("Unexpected configured ports: %v", status.PortsConfigured)
		}

		if status.Uptime <= 0 {
			t.Errorf("Uptime should be positive, got %v", status.Uptime)
		}
	})

	t.Run("GetServiceConfig", func(t *testing.T) {
		// Create config file for testing
		configContent := "3000\n8080\n"
		err := os.WriteFile(env.MockConfigFile, []byte(configContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create config file: %v", err)
		}

		config := service.GetServiceConfig()

		if config == nil {
			t.Fatalf("Config should not be nil")
		}

		if len(config.Ports) != 2 {
			t.Errorf("Expected 2 ports in config, got %d", len(config.Ports))
		}

		if config.ConfigPath != env.MockConfigFile {
			t.Errorf("Expected config path %s, got %s", env.MockConfigFile, config.ConfigPath)
		}
	})

	t.Run("ValidateConfiguration", func(t *testing.T) {
		// Create valid config file
		configContent := "3000\n8080\n"
		err := os.WriteFile(env.MockConfigFile, []byte(configContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create config file: %v", err)
		}

		errors := service.ValidateConfiguration()
		if len(errors) > 0 {
			t.Errorf("Valid configuration should have no errors, got: %v", errors)
		}

		// Test with invalid configuration (duplicate ports)
		service.config.Ports = []int{3000, 3000}
		errors = service.ValidateConfiguration()
		if len(errors) == 0 {
			t.Errorf("Invalid configuration should have errors")
		}

		// Check for specific error
		found := false
		for _, err := range errors {
			if strings.Contains(err, "Duplicate port") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Should detect duplicate port error")
		}
	})
}
