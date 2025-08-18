package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWebServiceModeInitialization tests the initialization of the service in web service mode
func TestWebServiceModeInitialization(t *testing.T) {
	// Create temporary config file for web service mode
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.txt")

	configContent := `# Test configuration for web service mode
3000
8080
5173

# Web service mode configuration
mode=web
web_port=8081
domain_patterns=*.test.dev,*.example.com
enable_rate_limit=false
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Parse deployment configuration
	deploymentConfig, err := parseDeploymentConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to parse deployment config: %v", err)
	}

	// Verify deployment mode
	if deploymentConfig.Mode != WebServiceMode {
		t.Errorf("Expected WebServiceMode, got %v", deploymentConfig.Mode)
	}

	// Verify web service configuration
	if deploymentConfig.WebConfig.Port != 8081 {
		t.Errorf("Expected web port 8081, got %d", deploymentConfig.WebConfig.Port)
	}

	expectedPatterns := []string{"*.test.dev", "*.example.com"}
	if len(deploymentConfig.WebConfig.DomainPatterns) != len(expectedPatterns) {
		t.Errorf("Expected %d domain patterns, got %d", len(expectedPatterns), len(deploymentConfig.WebConfig.DomainPatterns))
	}

	// Load port configuration
	ports, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load port config: %v", err)
	}

	expectedPorts := []int{3000, 8080, 5173}
	if len(ports) != len(expectedPorts) {
		t.Errorf("Expected %d ports, got %d", len(expectedPorts), len(ports))
	}

	// Create service configuration
	config := &Config{
		Ports:            ports,
		ConfigFilePath:   configPath,
		HostsBackupPath:  filepath.Join(tempDir, "hosts.backup"),
		LogLevel:         "INFO",
		DeploymentMode:   deploymentConfig.Mode,
		DeploymentConfig: deploymentConfig,
		WebServicePort:   deploymentConfig.WebConfig.Port,
		DomainPatterns:   deploymentConfig.WebConfig.DomainPatterns,
		EnableRateLimit:  deploymentConfig.WebConfig.RateLimit.Enabled,
		RateLimitRPS:     deploymentConfig.WebConfig.RateLimit.RPS,
	}

	// Create logger
	logger := log.New(io.Discard, "", 0) // Discard logs for testing

	// Create service instance
	service := NewPortRedirectService(config, logger, nil)

	// Verify service configuration
	if service.config.DeploymentMode != WebServiceMode {
		t.Errorf("Expected service deployment mode to be WebServiceMode, got %v", service.config.DeploymentMode)
	}

	if service.server.Addr != ":8081" {
		t.Errorf("Expected server address :8081, got %s", service.server.Addr)
	}

	// Verify hosts manager is nil for web service mode
	if service.hostsManager != nil {
		t.Error("Expected hosts manager to be nil for web service mode")
	}

	t.Log("Web service mode initialization test passed")
}

// TestLocalModeInitialization tests the initialization of the service in local mode
func TestLocalModeInitialization(t *testing.T) {
	// Create temporary config file for local mode
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.txt")
	hostsBackupPath := filepath.Join(tempDir, "hosts.backup")

	configContent := `# Test configuration for local mode
3000
8080
5173

# Local mode configuration (default)
mode=local
hosts_file_path=/etc/hosts
backup_path=` + hostsBackupPath + `
listen_port=80
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Parse deployment configuration
	deploymentConfig, err := parseDeploymentConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to parse deployment config: %v", err)
	}

	// Verify deployment mode
	if deploymentConfig.Mode != LocalMode {
		t.Errorf("Expected LocalMode, got %v", deploymentConfig.Mode)
	}

	// Load port configuration
	ports, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load port config: %v", err)
	}

	// Create service configuration
	config := &Config{
		Ports:            ports,
		ConfigFilePath:   configPath,
		HostsBackupPath:  hostsBackupPath,
		LogLevel:         "INFO",
		DeploymentMode:   deploymentConfig.Mode,
		DeploymentConfig: deploymentConfig,
	}

	// Create logger
	logger := log.New(io.Discard, "", 0) // Discard logs for testing

	// Create service instance
	service := NewPortRedirectService(config, logger, nil)

	// Verify service configuration
	if service.config.DeploymentMode != LocalMode {
		t.Errorf("Expected service deployment mode to be LocalMode, got %v", service.config.DeploymentMode)
	}

	if service.server.Addr != ":80" {
		t.Errorf("Expected server address :80, got %s", service.server.Addr)
	}

	// Verify hosts manager is created for local mode
	if service.hostsManager == nil {
		t.Error("Expected hosts manager to be created for local mode")
	}

	t.Log("Local mode initialization test passed")
}

// TestGracefulShutdownWebService tests graceful shutdown in web service mode
func TestGracefulShutdownWebService(t *testing.T) {
	// Create temporary config file for web service mode
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.txt")

	configContent := `3000
8080

mode=web
web_port=8082
domain_patterns=*.test.dev
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Parse deployment configuration
	deploymentConfig, err := parseDeploymentConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to parse deployment config: %v", err)
	}

	// Load port configuration
	ports, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load port config: %v", err)
	}

	// Create service configuration
	config := &Config{
		Ports:            ports,
		ConfigFilePath:   configPath,
		HostsBackupPath:  filepath.Join(tempDir, "hosts.backup"),
		LogLevel:         "INFO",
		DeploymentMode:   deploymentConfig.Mode,
		DeploymentConfig: deploymentConfig,
		WebServicePort:   deploymentConfig.WebConfig.Port,
		DomainPatterns:   deploymentConfig.WebConfig.DomainPatterns,
	}

	// Create logger
	logger := log.New(io.Discard, "", 0)

	// Create and start service
	service := NewPortRedirectService(config, logger, nil)

	if err := service.Start(); err != nil {
		t.Fatalf("Failed to start service: %v", err)
	}

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Test that the server is running by making a request
	client := &http.Client{
		Timeout: 1 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Get("http://localhost:8082/")
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	resp.Body.Close()

	// Test graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := service.Stop(ctx); err != nil {
		t.Errorf("Failed to stop service gracefully: %v", err)
	}

	// Test cleanup
	if err := service.Cleanup(); err != nil {
		t.Errorf("Failed to cleanup service: %v", err)
	}

	t.Log("Graceful shutdown test passed")
}

// TestGracefulShutdownLocal tests graceful shutdown in local mode
func TestGracefulShutdownLocal(t *testing.T) {
	// Create temporary config file for local mode
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.txt")
	hostsBackupPath := filepath.Join(tempDir, "hosts.backup")

	configContent := `3000
8080

mode=local
backup_path=` + hostsBackupPath + `
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Parse deployment configuration
	deploymentConfig, err := parseDeploymentConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to parse deployment config: %v", err)
	}

	// Load port configuration
	ports, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load port config: %v", err)
	}

	// Create service configuration
	config := &Config{
		Ports:            ports,
		ConfigFilePath:   configPath,
		HostsBackupPath:  hostsBackupPath,
		LogLevel:         "INFO",
		DeploymentMode:   deploymentConfig.Mode,
		DeploymentConfig: deploymentConfig,
	}

	// Create logger
	logger := log.New(io.Discard, "", 0)

	// Create service (don't start it since we can't bind to port 80 in tests)
	service := NewPortRedirectService(config, logger, nil)

	// Test cleanup without starting (should handle gracefully)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := service.Stop(ctx); err != nil {
		// This is expected since the server was never started
		t.Logf("Expected error stopping unstarted server: %v", err)
	}

	// Test cleanup
	if err := service.Cleanup(); err != nil {
		// Check if it's a hosts file related error (expected in test environment)
		if !strings.Contains(err.Error(), "hosts") {
			t.Errorf("Unexpected cleanup error: %v", err)
		}
	}

	t.Log("Local mode shutdown test passed")
}

// TestConfigurationValidation tests configuration validation for both modes
func TestConfigurationValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid web service config",
			config: `3000
8080

mode=web
web_port=8080
domain_patterns=*.test.dev,*.example.com
`,
			expectError: false,
		},
		{
			name: "Valid local mode config",
			config: `3000
8080

mode=local
`,
			expectError: false,
		},
		{
			name: "Invalid deployment mode",
			config: `3000

mode=invalid
`,
			expectError: true,
			errorMsg:    "invalid deployment mode",
		},
		{
			name: "Web service without domain patterns",
			config: `3000

mode=web
web_port=8080
`,
			expectError: false, // Should parse but fail validation later
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, "config.txt")

			if err := os.WriteFile(configPath, []byte(tt.config), 0644); err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			_, err := parseDeploymentConfig(configPath)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
