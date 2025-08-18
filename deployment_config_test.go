package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeploymentModeString tests the String method of DeploymentMode
func TestDeploymentModeString(t *testing.T) {
	tests := []struct {
		mode     DeploymentMode
		expected string
	}{
		{LocalMode, "local"},
		{WebServiceMode, "web"},
		{DeploymentMode(999), "unknown"},
	}

	for _, test := range tests {
		result := test.mode.String()
		if result != test.expected {
			t.Errorf("DeploymentMode(%d).String() = %s, expected %s", test.mode, result, test.expected)
		}
	}
}

// TestParseDeploymentMode tests parsing deployment mode from strings
func TestParseDeploymentMode(t *testing.T) {
	tests := []struct {
		input       string
		expected    DeploymentMode
		expectError bool
	}{
		{"local", LocalMode, false},
		{"Local", LocalMode, false},
		{"LOCAL", LocalMode, false},
		{" local ", LocalMode, false},
		{"web", WebServiceMode, false},
		{"Web", WebServiceMode, false},
		{"WEB", WebServiceMode, false},
		{"webservice", WebServiceMode, false},
		{"web-service", WebServiceMode, false},
		{" web ", WebServiceMode, false},
		{"invalid", LocalMode, true},
		{"", LocalMode, true},
		{"production", LocalMode, true},
	}

	for _, test := range tests {
		result, err := ParseDeploymentMode(test.input)

		if test.expectError {
			if err == nil {
				t.Errorf("ParseDeploymentMode(%q) expected error but got none", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseDeploymentMode(%q) unexpected error: %v", test.input, err)
			}
			if result != test.expected {
				t.Errorf("ParseDeploymentMode(%q) = %v, expected %v", test.input, result, test.expected)
			}
		}
	}
}

// TestParseDeploymentConfig tests parsing deployment configuration from files
func TestParseDeploymentConfig(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "deployment-config-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name        string
		content     string
		expectError bool
		validate    func(*testing.T, *DeploymentConfig)
	}{
		{
			name: "default_local_mode",
			content: `# Default configuration
3000
8080`,
			expectError: false,
			validate: func(t *testing.T, config *DeploymentConfig) {
				if config.Mode != LocalMode {
					t.Errorf("Expected LocalMode, got %v", config.Mode)
				}
				if config.LocalConfig == nil {
					t.Error("LocalConfig should not be nil")
				}
				if config.WebConfig == nil {
					t.Error("WebConfig should not be nil (default)")
				}
			},
		},
		{
			name: "web_service_mode",
			content: `3000
8080
mode=web
web_port=9000
domain_patterns=*.example.com,*.test.dev
enable_rate_limit=true
rate_limit_rps=50`,
			expectError: false,
			validate: func(t *testing.T, config *DeploymentConfig) {
				if config.Mode != WebServiceMode {
					t.Errorf("Expected WebServiceMode, got %v", config.Mode)
				}
				if config.WebConfig.Port != 9000 {
					t.Errorf("Expected web port 9000, got %d", config.WebConfig.Port)
				}
				expectedPatterns := []string{"*.example.com", "*.test.dev"}
				if len(config.WebConfig.DomainPatterns) != len(expectedPatterns) {
					t.Errorf("Expected %d domain patterns, got %d", len(expectedPatterns), len(config.WebConfig.DomainPatterns))
				}
				for i, pattern := range expectedPatterns {
					if config.WebConfig.DomainPatterns[i] != pattern {
						t.Errorf("Expected domain pattern %s, got %s", pattern, config.WebConfig.DomainPatterns[i])
					}
				}
				if !config.WebConfig.RateLimit.Enabled {
					t.Error("Expected rate limiting to be enabled")
				}
				if config.WebConfig.RateLimit.RPS != 50 {
					t.Errorf("Expected rate limit RPS 50, got %d", config.WebConfig.RateLimit.RPS)
				}
			},
		},
		{
			name: "local_mode_custom",
			content: `3000
mode=local
hosts_file_path=/custom/hosts
backup_path=/custom/backup
listen_port=8080`,
			expectError: false,
			validate: func(t *testing.T, config *DeploymentConfig) {
				if config.Mode != LocalMode {
					t.Errorf("Expected LocalMode, got %v", config.Mode)
				}
				if config.LocalConfig.HostsFilePath != "/custom/hosts" {
					t.Errorf("Expected hosts file path /custom/hosts, got %s", config.LocalConfig.HostsFilePath)
				}
				if config.LocalConfig.BackupPath != "/custom/backup" {
					t.Errorf("Expected backup path /custom/backup, got %s", config.LocalConfig.BackupPath)
				}
				if config.LocalConfig.ListenPort != 8080 {
					t.Errorf("Expected listen port 8080, got %d", config.LocalConfig.ListenPort)
				}
			},
		},
		{
			name: "invalid_mode",
			content: `3000
mode=invalid`,
			expectError: true,
			validate:    nil,
		},
		{
			name: "invalid_web_port",
			content: `3000
mode=web
web_port=70000`,
			expectError: true,
			validate:    nil,
		},
		{
			name: "invalid_rate_limit_rps",
			content: `3000
mode=web
domain_patterns=*.example.com
rate_limit_rps=-1`,
			expectError: true,
			validate:    nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(tempDir, test.name+".txt")

			if err := os.WriteFile(configPath, []byte(test.content), 0644); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			config, err := parseDeploymentConfig(configPath)

			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if test.validate != nil {
					test.validate(t, config)
				}
			}
		})
	}
}

// TestValidateDeploymentConfig tests deployment configuration validation
func TestValidateDeploymentConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *DeploymentConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil_config",
			config:      nil,
			expectError: true,
			errorMsg:    "deployment configuration is nil",
		},
		{
			name: "valid_local_config",
			config: &DeploymentConfig{
				Mode: LocalMode,
				LocalConfig: &LocalModeConfig{
					HostsFilePath: "/etc/hosts",
					BackupPath:    "/etc/backup",
					ListenPort:    80,
				},
			},
			expectError: false,
		},
		{
			name: "valid_web_config",
			config: &DeploymentConfig{
				Mode: WebServiceMode,
				WebConfig: &WebServiceConfig{
					Port:           8080,
					DomainPatterns: []string{"*.example.com"},
					RateLimit: struct {
						Enabled bool `json:"enabled"`
						RPS     int  `json:"rps"`
						Burst   int  `json:"burst"`
					}{
						Enabled: false,
						RPS:     100,
						Burst:   10,
					},
				},
			},
			expectError: false,
		},
		{
			name: "local_mode_missing_config",
			config: &DeploymentConfig{
				Mode:        LocalMode,
				LocalConfig: nil,
			},
			expectError: true,
			errorMsg:    "local mode configuration is missing",
		},
		{
			name: "web_mode_missing_config",
			config: &DeploymentConfig{
				Mode:      WebServiceMode,
				WebConfig: nil,
			},
			expectError: true,
			errorMsg:    "web service mode configuration is missing",
		},
		{
			name: "invalid_deployment_mode",
			config: &DeploymentConfig{
				Mode: DeploymentMode(999),
			},
			expectError: true,
			errorMsg:    "invalid deployment mode",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateDeploymentConfig(test.config)

			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if test.errorMsg != "" && !strings.Contains(err.Error(), test.errorMsg) {
					t.Errorf("Expected error message to contain %q, got %q", test.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateLocalModeConfig tests local mode configuration validation
func TestValidateLocalModeConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *LocalModeConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil_config",
			config:      nil,
			expectError: true,
			errorMsg:    "local mode configuration is nil",
		},
		{
			name: "valid_config",
			config: &LocalModeConfig{
				HostsFilePath: "/etc/hosts",
				BackupPath:    "/etc/backup",
				ListenPort:    80,
			},
			expectError: false,
		},
		{
			name: "empty_hosts_path",
			config: &LocalModeConfig{
				HostsFilePath: "",
				BackupPath:    "/etc/backup",
				ListenPort:    80,
			},
			expectError: true,
			errorMsg:    "hosts file path cannot be empty",
		},
		{
			name: "empty_backup_path",
			config: &LocalModeConfig{
				HostsFilePath: "/etc/hosts",
				BackupPath:    "",
				ListenPort:    80,
			},
			expectError: true,
			errorMsg:    "backup path cannot be empty",
		},
		{
			name: "invalid_port_low",
			config: &LocalModeConfig{
				HostsFilePath: "/etc/hosts",
				BackupPath:    "/etc/backup",
				ListenPort:    0,
			},
			expectError: true,
			errorMsg:    "listen port 0 is out of valid range",
		},
		{
			name: "invalid_port_high",
			config: &LocalModeConfig{
				HostsFilePath: "/etc/hosts",
				BackupPath:    "/etc/backup",
				ListenPort:    70000,
			},
			expectError: true,
			errorMsg:    "listen port 70000 is out of valid range",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateLocalModeConfig(test.config)

			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if test.errorMsg != "" && !strings.Contains(err.Error(), test.errorMsg) {
					t.Errorf("Expected error message to contain %q, got %q", test.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateWebServiceConfig tests web service configuration validation
func TestValidateWebServiceConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *WebServiceConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil_config",
			config:      nil,
			expectError: true,
			errorMsg:    "web service configuration is nil",
		},
		{
			name: "valid_config",
			config: &WebServiceConfig{
				Port:           8080,
				DomainPatterns: []string{"*.example.com"},
				RateLimit: struct {
					Enabled bool `json:"enabled"`
					RPS     int  `json:"rps"`
					Burst   int  `json:"burst"`
				}{
					Enabled: false,
					RPS:     100,
					Burst:   10,
				},
			},
			expectError: false,
		},
		{
			name: "invalid_port_low",
			config: &WebServiceConfig{
				Port:           0,
				DomainPatterns: []string{"*.example.com"},
			},
			expectError: true,
			errorMsg:    "web service port 0 is out of valid range",
		},
		{
			name: "invalid_port_high",
			config: &WebServiceConfig{
				Port:           70000,
				DomainPatterns: []string{"*.example.com"},
			},
			expectError: true,
			errorMsg:    "web service port 70000 is out of valid range",
		},
		{
			name: "no_domain_patterns",
			config: &WebServiceConfig{
				Port:           8080,
				DomainPatterns: []string{},
			},
			expectError: true,
			errorMsg:    "web service mode requires at least one domain pattern",
		},
		{
			name: "invalid_domain_pattern",
			config: &WebServiceConfig{
				Port:           8080,
				DomainPatterns: []string{"invalid pattern with spaces"},
			},
			expectError: true,
			errorMsg:    "invalid domain pattern",
		},
		{
			name: "rate_limit_enabled_invalid_rps",
			config: &WebServiceConfig{
				Port:           8080,
				DomainPatterns: []string{"*.example.com"},
				RateLimit: struct {
					Enabled bool `json:"enabled"`
					RPS     int  `json:"rps"`
					Burst   int  `json:"burst"`
				}{
					Enabled: true,
					RPS:     0,
					Burst:   10,
				},
			},
			expectError: true,
			errorMsg:    "rate limit RPS must be positive",
		},
		{
			name: "rate_limit_enabled_invalid_burst",
			config: &WebServiceConfig{
				Port:           8080,
				DomainPatterns: []string{"*.example.com"},
				RateLimit: struct {
					Enabled bool `json:"enabled"`
					RPS     int  `json:"rps"`
					Burst   int  `json:"burst"`
				}{
					Enabled: true,
					RPS:     100,
					Burst:   0,
				},
			},
			expectError: true,
			errorMsg:    "rate limit burst must be positive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateWebServiceConfig(test.config)

			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if test.errorMsg != "" && !strings.Contains(err.Error(), test.errorMsg) {
					t.Errorf("Expected error message to contain %q, got %q", test.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateDomainPattern tests domain pattern validation
func TestValidateDomainPattern(t *testing.T) {
	tests := []struct {
		pattern     string
		expectError bool
		errorMsg    string
	}{
		{"*.example.com", false, ""},
		{"example.com", false, ""},
		{"sub.example.com", false, ""},
		{"test-domain.dev", false, ""},
		{"123.example.com", false, ""},
		{"", true, "domain pattern cannot be empty"},
		{"example", true, "domain pattern must contain at least one dot"},
		{"*.*.example.com", true, "wildcard (*) can only be used at the beginning"},
		{"example.*.com", true, "wildcard (*) can only be used at the beginning"},
		{"example com", true, "domain pattern contains invalid characters"},
		{"example@com", true, "domain pattern contains invalid characters"},
		{"example$.com", true, "domain pattern contains invalid characters"},
	}

	for _, test := range tests {
		t.Run(test.pattern, func(t *testing.T) {
			err := validateDomainPattern(test.pattern)

			if test.expectError {
				if err == nil {
					t.Errorf("Expected error for pattern %q but got none", test.pattern)
				} else if test.errorMsg != "" && !strings.Contains(err.Error(), test.errorMsg) {
					t.Errorf("Expected error message to contain %q, got %q", test.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for pattern %q: %v", test.pattern, err)
				}
			}
		})
	}
}

// TestLoadFullConfig tests loading complete configuration including deployment settings
func TestLoadFullConfig(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "full-config-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name        string
		content     string
		expectError bool
		validate    func(*testing.T, []int, *DeploymentConfig)
	}{
		{
			name: "valid_local_config",
			content: `3000
8080
5173
mode=local`,
			expectError: false,
			validate: func(t *testing.T, ports []int, config *DeploymentConfig) {
				expectedPorts := []int{3000, 8080, 5173}
				if len(ports) != len(expectedPorts) {
					t.Errorf("Expected %d ports, got %d", len(expectedPorts), len(ports))
				}
				for i, port := range expectedPorts {
					if ports[i] != port {
						t.Errorf("Expected port %d, got %d", port, ports[i])
					}
				}
				if config.Mode != LocalMode {
					t.Errorf("Expected LocalMode, got %v", config.Mode)
				}
			},
		},
		{
			name: "valid_web_config",
			content: `3000
8080
mode=web
web_port=9000
domain_patterns=*.example.com`,
			expectError: false,
			validate: func(t *testing.T, ports []int, config *DeploymentConfig) {
				expectedPorts := []int{3000, 8080}
				if len(ports) != len(expectedPorts) {
					t.Errorf("Expected %d ports, got %d", len(expectedPorts), len(ports))
				}
				if config.Mode != WebServiceMode {
					t.Errorf("Expected WebServiceMode, got %v", config.Mode)
				}
				if config.WebConfig.Port != 9000 {
					t.Errorf("Expected web port 9000, got %d", config.WebConfig.Port)
				}
			},
		},
		{
			name: "invalid_web_config_no_domain",
			content: `3000
mode=web
web_port=8080`,
			expectError: true,
			validate:    nil,
		},
		{
			name: "invalid_port_in_config",
			content: `70000
mode=local`,
			expectError: true,
			validate:    nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(tempDir, test.name+".txt")

			if err := os.WriteFile(configPath, []byte(test.content), 0644); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			ports, config, err := loadFullConfig(configPath)

			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if test.validate != nil {
					test.validate(t, ports, config)
				}
			}
		})
	}
}
