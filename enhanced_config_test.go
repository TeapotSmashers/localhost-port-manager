package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnhancedConfigParsing tests the enhanced configuration parsing with backward compatibility
func TestEnhancedConfigParsing(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "enhanced-config-test-*")
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
			name: "legacy_config_backward_compatibility",
			content: `# Legacy configuration file
3000
8080
5173`,
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
					t.Errorf("Expected LocalMode for legacy config, got %v", config.Mode)
				}
				if config.LocalConfig == nil {
					t.Error("LocalConfig should not be nil for legacy config")
				}
				if config.LocalConfig.HostsFilePath != DefaultHostsPath {
					t.Errorf("Expected default hosts path, got %s", config.LocalConfig.HostsFilePath)
				}
			},
		},
		{
			name: "enhanced_local_mode_config",
			content: `# Enhanced local mode configuration
3000
8080
mode=local
hosts_file_path=/custom/hosts
backup_path=/custom/backup
listen_port=8080`,
			expectError: false,
			validate: func(t *testing.T, ports []int, config *DeploymentConfig) {
				if config.Mode != LocalMode {
					t.Errorf("Expected LocalMode, got %v", config.Mode)
				}
				if config.LocalConfig.HostsFilePath != "/custom/hosts" {
					t.Errorf("Expected custom hosts path, got %s", config.LocalConfig.HostsFilePath)
				}
				if config.LocalConfig.BackupPath != "/custom/backup" {
					t.Errorf("Expected custom backup path, got %s", config.LocalConfig.BackupPath)
				}
				if config.LocalConfig.ListenPort != 8080 {
					t.Errorf("Expected listen port 8080, got %d", config.LocalConfig.ListenPort)
				}
			},
		},
		{
			name: "enhanced_web_service_config",
			content: `# Enhanced web service configuration
3000
8080
5173
mode=web
web_port=9000
domain_patterns=*.example.com,*.test.dev,sub.domain.com
enable_rate_limit=true
rate_limit_rps=50
rate_limit_burst=20`,
			expectError: false,
			validate: func(t *testing.T, ports []int, config *DeploymentConfig) {
				if config.Mode != WebServiceMode {
					t.Errorf("Expected WebServiceMode, got %v", config.Mode)
				}
				if config.WebConfig.Port != 9000 {
					t.Errorf("Expected web port 9000, got %d", config.WebConfig.Port)
				}
				expectedPatterns := []string{"*.example.com", "*.test.dev", "sub.domain.com"}
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
				if config.WebConfig.RateLimit.Burst != 20 {
					t.Errorf("Expected rate limit burst 20, got %d", config.WebConfig.RateLimit.Burst)
				}
			},
		},
		{
			name: "alternative_key_names",
			content: `3000
deployment_mode=web
web_service_port=7000
domains=*.alt.com
rate_limit_enabled=true
rate_limit_requests_per_second=200
hosts_path=/alt/hosts
hosts_backup_path=/alt/backup`,
			expectError: false,
			validate: func(t *testing.T, ports []int, config *DeploymentConfig) {
				if config.Mode != WebServiceMode {
					t.Errorf("Expected WebServiceMode, got %v", config.Mode)
				}
				if config.WebConfig.Port != 7000 {
					t.Errorf("Expected web port 7000, got %d", config.WebConfig.Port)
				}
				if len(config.WebConfig.DomainPatterns) != 1 || config.WebConfig.DomainPatterns[0] != "*.alt.com" {
					t.Errorf("Expected domain pattern *.alt.com, got %v", config.WebConfig.DomainPatterns)
				}
				if config.WebConfig.RateLimit.RPS != 200 {
					t.Errorf("Expected rate limit RPS 200, got %d", config.WebConfig.RateLimit.RPS)
				}
				if config.LocalConfig.HostsFilePath != "/alt/hosts" {
					t.Errorf("Expected hosts path /alt/hosts, got %s", config.LocalConfig.HostsFilePath)
				}
			},
		},
		{
			name: "invalid_domain_pattern",
			content: `3000
mode=web
web_port=8080
domain_patterns=invalid pattern with spaces`,
			expectError: true,
		},
		{
			name: "empty_required_field",
			content: `3000
mode=local
hosts_file_path=`,
			expectError: true,
		},
		{
			name: "invalid_port_range",
			content: `3000
mode=web
web_port=70000`,
			expectError: true,
		},
		{
			name: "negative_rate_limit",
			content: `3000
mode=web
domain_patterns=*.example.com
rate_limit_rps=-1`,
			expectError: true,
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

// TestConfigMigrationManager tests the configuration migration functionality
func TestConfigMigrationManager(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-migration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logger := NewStructuredLogger(nil) // Use nil logger for tests
	manager := NewConfigMigrationManager(logger)

	t.Run("detect_legacy_config", func(t *testing.T) {
		legacyConfig := `# Legacy configuration
3000
8080
5173`
		configPath := filepath.Join(tempDir, "legacy.txt")
		if err := os.WriteFile(configPath, []byte(legacyConfig), 0644); err != nil {
			t.Fatalf("Failed to write legacy config: %v", err)
		}

		version, err := manager.DetectConfigVersion(configPath)
		if err != nil {
			t.Errorf("Failed to detect config version: %v", err)
		}
		if version != "legacy" {
			t.Errorf("Expected legacy version, got %s", version)
		}

		needsMigration, targetVersion, err := manager.NeedsMigration(configPath)
		if err != nil {
			t.Errorf("Failed to check migration status: %v", err)
		}
		if !needsMigration {
			t.Error("Legacy config should need migration")
		}
		if targetVersion != "v1.0" {
			t.Errorf("Expected target version v1.0, got %s", targetVersion)
		}
	})

	t.Run("detect_enhanced_config", func(t *testing.T) {
		enhancedConfig := `3000
8080
mode=local`
		configPath := filepath.Join(tempDir, "enhanced.txt")
		if err := os.WriteFile(configPath, []byte(enhancedConfig), 0644); err != nil {
			t.Fatalf("Failed to write enhanced config: %v", err)
		}

		version, err := manager.DetectConfigVersion(configPath)
		if err != nil {
			t.Errorf("Failed to detect config version: %v", err)
		}
		if version != "v1.0" {
			t.Errorf("Expected v1.0 version, got %s", version)
		}

		needsMigration, _, err := manager.NeedsMigration(configPath)
		if err != nil {
			t.Errorf("Failed to check migration status: %v", err)
		}
		if needsMigration {
			t.Error("Enhanced config should not need migration")
		}
	})

	t.Run("migrate_legacy_to_v1", func(t *testing.T) {
		legacyConfig := `# Legacy configuration
3000
8080
5173`
		configPath := filepath.Join(tempDir, "migrate.txt")
		if err := os.WriteFile(configPath, []byte(legacyConfig), 0644); err != nil {
			t.Fatalf("Failed to write legacy config: %v", err)
		}

		// Perform migration
		err := manager.MigrateConfig(configPath)
		if err != nil {
			t.Errorf("Migration failed: %v", err)
		}

		// Verify migration result
		content, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read migrated config: %v", err)
		}

		contentStr := string(content)
		if !strings.Contains(contentStr, "mode=local") {
			t.Error("Migrated config should contain mode=local")
		}
		if !strings.Contains(contentStr, "3000") {
			t.Error("Migrated config should preserve original ports")
		}
		if !strings.Contains(contentStr, "8080") {
			t.Error("Migrated config should preserve original ports")
		}
		if !strings.Contains(contentStr, "5173") {
			t.Error("Migrated config should preserve original ports")
		}

		// Verify backup was created
		backupFiles, err := filepath.Glob(configPath + ".backup.*")
		if err != nil {
			t.Errorf("Failed to check for backup files: %v", err)
		}
		if len(backupFiles) == 0 {
			t.Error("Migration should create a backup file")
		}

		// Verify the migrated config can be parsed
		_, _, err = loadFullConfig(configPath)
		if err != nil {
			t.Errorf("Migrated config should be parseable: %v", err)
		}
	})

	t.Run("migration_already_enhanced", func(t *testing.T) {
		enhancedConfig := `3000
mode=local`
		configPath := filepath.Join(tempDir, "already_enhanced.txt")
		if err := os.WriteFile(configPath, []byte(enhancedConfig), 0644); err != nil {
			t.Fatalf("Failed to write enhanced config: %v", err)
		}

		// Try to migrate (should be no-op)
		err := manager.MigrateConfig(configPath)
		if err != nil {
			t.Errorf("Migration of already enhanced config should succeed: %v", err)
		}

		// Content should remain unchanged
		content, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config after migration: %v", err)
		}

		if string(content) != enhancedConfig {
			t.Error("Enhanced config should not be modified during migration")
		}
	})
}

// TestValidateConfigFormat tests configuration format validation
func TestValidateConfigFormat(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-validation-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name        string
		content     string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_legacy_config",
			content: `3000
8080`,
			expectError: false,
		},
		{
			name: "valid_enhanced_config",
			content: `3000
8080
mode=local`,
			expectError: false,
		},
		{
			name: "valid_web_config",
			content: `3000
mode=web
web_port=8080
domain_patterns=*.example.com`,
			expectError: false,
		},
		{
			name: "invalid_port",
			content: `70000
mode=local`,
			expectError: true,
			errorMsg:    "port number 70000",
		},
		{
			name: "invalid_mode",
			content: `3000
mode=invalid`,
			expectError: true,
			errorMsg:    "invalid deployment mode",
		},
		{
			name: "web_mode_no_domains",
			content: `3000
mode=web
web_port=8080`,
			expectError: true,
			errorMsg:    "at least one domain pattern",
		},
		{
			name: "invalid_domain_pattern",
			content: `3000
mode=web
web_port=8080
domain_patterns=invalid pattern`,
			expectError: true,
			errorMsg:    "invalid domain pattern",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(tempDir, test.name+".txt")

			if err := os.WriteFile(configPath, []byte(test.content), 0644); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			err := ValidateConfigFormat(configPath)

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

// TestCreateConfigTemplate tests configuration template creation
func TestCreateConfigTemplate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-template-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name         string
		mode         DeploymentMode
		validateFunc func(*testing.T, string)
	}{
		{
			name: "local_mode_template",
			mode: LocalMode,
			validateFunc: func(t *testing.T, content string) {
				if !strings.Contains(content, "mode=local") {
					t.Error("Local mode template should contain mode=local")
				}
				if !strings.Contains(content, "hosts_file_path=/etc/hosts") {
					t.Error("Local mode template should contain hosts_file_path")
				}
				if !strings.Contains(content, "# web_port=8080") {
					t.Error("Local mode template should have commented web service settings")
				}
			},
		},
		{
			name: "web_service_template",
			mode: WebServiceMode,
			validateFunc: func(t *testing.T, content string) {
				if !strings.Contains(content, "mode=web") {
					t.Error("Web service template should contain mode=web")
				}
				if !strings.Contains(content, "web_port=8080") {
					t.Error("Web service template should contain web_port")
				}
				if !strings.Contains(content, "domain_patterns=") {
					t.Error("Web service template should contain domain_patterns")
				}
				if !strings.Contains(content, "# hosts_file_path=/etc/hosts") {
					t.Error("Web service template should have commented local mode settings")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(tempDir, test.name+".txt")

			err := CreateConfigTemplate(configPath, test.mode)
			if err != nil {
				t.Errorf("Failed to create config template: %v", err)
			}

			// Verify file was created
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				t.Error("Config template file was not created")
			}

			// Read and validate content
			content, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("Failed to read template file: %v", err)
			}

			contentStr := string(content)

			// Common validations
			if !strings.Contains(contentStr, "3000") {
				t.Error("Template should contain default ports")
			}
			if !strings.Contains(contentStr, "8080") {
				t.Error("Template should contain default ports")
			}

			// Mode-specific validations
			if test.validateFunc != nil {
				test.validateFunc(t, contentStr)
			}

			// Verify the template can be parsed
			err = ValidateConfigFormat(configPath)
			if err != nil {
				t.Errorf("Generated template should be valid: %v", err)
			}
		})
	}
}

// TestBackwardCompatibilityDefaults tests the backward compatibility default application
func TestBackwardCompatibilityDefaults(t *testing.T) {
	// Test with minimal config
	config := &DeploymentConfig{}

	result := applyBackwardCompatibilityDefaults(config)

	if result.Mode != LocalMode {
		t.Errorf("Expected LocalMode, got %v", result.Mode)
	}

	if result.LocalConfig == nil {
		t.Fatal("LocalConfig should not be nil after applying defaults")
	}

	if result.LocalConfig.HostsFilePath != DefaultHostsPath {
		t.Errorf("Expected default hosts path %s, got %s", DefaultHostsPath, result.LocalConfig.HostsFilePath)
	}

	if result.LocalConfig.BackupPath != DefaultBackupPath {
		t.Errorf("Expected default backup path %s, got %s", DefaultBackupPath, result.LocalConfig.BackupPath)
	}

	if result.LocalConfig.ListenPort != 80 {
		t.Errorf("Expected default listen port 80, got %d", result.LocalConfig.ListenPort)
	}
}

// TestConfigKeyValueParsing tests individual key-value pair parsing
func TestConfigKeyValueParsing(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		value       string
		expectError bool
		validate    func(*testing.T, *DeploymentConfig)
	}{
		{
			name:  "mode_local",
			key:   "mode",
			value: "local",
			validate: func(t *testing.T, config *DeploymentConfig) {
				if config.Mode != LocalMode {
					t.Errorf("Expected LocalMode, got %v", config.Mode)
				}
			},
		},
		{
			name:  "mode_web",
			key:   "mode",
			value: "web",
			validate: func(t *testing.T, config *DeploymentConfig) {
				if config.Mode != WebServiceMode {
					t.Errorf("Expected WebServiceMode, got %v", config.Mode)
				}
			},
		},
		{
			name:        "invalid_mode",
			key:         "mode",
			value:       "invalid",
			expectError: true,
		},
		{
			name:  "web_port",
			key:   "web_port",
			value: "9000",
			validate: func(t *testing.T, config *DeploymentConfig) {
				if config.WebConfig.Port != 9000 {
					t.Errorf("Expected web port 9000, got %d", config.WebConfig.Port)
				}
			},
		},
		{
			name:        "invalid_web_port",
			key:         "web_port",
			value:       "invalid",
			expectError: true,
		},
		{
			name:        "web_port_out_of_range",
			key:         "web_port",
			value:       "70000",
			expectError: true,
		},
		{
			name:  "domain_patterns",
			key:   "domain_patterns",
			value: "*.example.com,*.test.dev",
			validate: func(t *testing.T, config *DeploymentConfig) {
				expected := []string{"*.example.com", "*.test.dev"}
				if len(config.WebConfig.DomainPatterns) != len(expected) {
					t.Errorf("Expected %d patterns, got %d", len(expected), len(config.WebConfig.DomainPatterns))
				}
				for i, pattern := range expected {
					if config.WebConfig.DomainPatterns[i] != pattern {
						t.Errorf("Expected pattern %s, got %s", pattern, config.WebConfig.DomainPatterns[i])
					}
				}
			},
		},
		{
			name:        "invalid_domain_pattern",
			key:         "domain_patterns",
			value:       "invalid pattern",
			expectError: true,
		},
		{
			name:  "rate_limit_enabled",
			key:   "enable_rate_limit",
			value: "true",
			validate: func(t *testing.T, config *DeploymentConfig) {
				if !config.WebConfig.RateLimit.Enabled {
					t.Error("Expected rate limiting to be enabled")
				}
			},
		},
		{
			name:        "invalid_rate_limit_enabled",
			key:         "enable_rate_limit",
			value:       "invalid",
			expectError: true,
		},
		{
			name:        "empty_hosts_path",
			key:         "hosts_file_path",
			value:       "",
			expectError: true,
		},
		{
			name:        "empty_backup_path",
			key:         "backup_path",
			value:       "",
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &DeploymentConfig{
				Mode: LocalMode,
				LocalConfig: &LocalModeConfig{
					HostsFilePath: DefaultHostsPath,
					BackupPath:    DefaultBackupPath,
					ListenPort:    80,
				},
				WebConfig: &WebServiceConfig{
					Port:           8080,
					DomainPatterns: []string{},
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
			}

			err := parseConfigKeyValue(config, test.key, test.value, 1)

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

// TestRealWorldEnhancedConfig tests a real-world enhanced configuration file
func TestRealWorldEnhancedConfig(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "real-world-config-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a realistic enhanced configuration
	configContent := `# Enhanced Configuration for Web Service Deployment
# Common development ports
3000
8080
5173
9000

# Deployment mode: local or web
mode=web

# Web service specific settings
web_port=8080
domain_patterns=*.sankalpmukim.dev,*.example.com,*.test.local

# Rate limiting configuration
enable_rate_limit=true
rate_limit_rps=100
rate_limit_burst=20

# Local mode settings (commented out for web mode)
# hosts_file_path=/etc/hosts
# backup_path=/etc/port-redirect/hosts.backup
# listen_port=80`

	configPath := filepath.Join(tempDir, "enhanced_config.txt")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Test loading the configuration
	ports, config, err := loadFullConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load configuration: %v", err)
	}

	// Verify ports
	expectedPorts := []int{3000, 8080, 5173, 9000}
	if len(ports) != len(expectedPorts) {
		t.Errorf("Expected %d ports, got %d", len(expectedPorts), len(ports))
	}
	for i, expectedPort := range expectedPorts {
		if ports[i] != expectedPort {
			t.Errorf("Expected port %d at index %d, got %d", expectedPort, i, ports[i])
		}
	}

	// Verify deployment mode
	if config.Mode != WebServiceMode {
		t.Errorf("Expected WebServiceMode, got %v", config.Mode)
	}

	// Verify web service configuration
	if config.WebConfig.Port != 8080 {
		t.Errorf("Expected web port 8080, got %d", config.WebConfig.Port)
	}

	expectedPatterns := []string{"*.sankalpmukim.dev", "*.example.com", "*.test.local"}
	if len(config.WebConfig.DomainPatterns) != len(expectedPatterns) {
		t.Errorf("Expected %d domain patterns, got %d", len(expectedPatterns), len(config.WebConfig.DomainPatterns))
	}
	for i, expectedPattern := range expectedPatterns {
		if config.WebConfig.DomainPatterns[i] != expectedPattern {
			t.Errorf("Expected domain pattern %s at index %d, got %s", expectedPattern, i, config.WebConfig.DomainPatterns[i])
		}
	}

	// Verify rate limiting configuration
	if !config.WebConfig.RateLimit.Enabled {
		t.Error("Expected rate limiting to be enabled")
	}
	if config.WebConfig.RateLimit.RPS != 100 {
		t.Errorf("Expected rate limit RPS 100, got %d", config.WebConfig.RateLimit.RPS)
	}
	if config.WebConfig.RateLimit.Burst != 20 {
		t.Errorf("Expected rate limit burst 20, got %d", config.WebConfig.RateLimit.Burst)
	}

	// Test configuration validation
	err = ValidateConfigFormat(configPath)
	if err != nil {
		t.Errorf("Configuration validation should pass: %v", err)
	}

	t.Logf("Successfully loaded and validated enhanced configuration:")
	t.Logf("  Ports: %v", ports)
	t.Logf("  Mode: %s", config.Mode.String())
	t.Logf("  Web Port: %d", config.WebConfig.Port)
	t.Logf("  Domain Patterns: %v", config.WebConfig.DomainPatterns)
	t.Logf("  Rate Limiting: enabled=%v, rps=%d, burst=%d",
		config.WebConfig.RateLimit.Enabled,
		config.WebConfig.RateLimit.RPS,
		config.WebConfig.RateLimit.Burst)
}

// TestConfigMigrationRealWorld tests migration from legacy to enhanced format
func TestConfigMigrationRealWorld(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "migration-real-world-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a legacy configuration file
	legacyContent := `# Legacy configuration file
# Common development ports
3000
8080
5173
9000`

	configPath := filepath.Join(tempDir, "legacy_config.txt")
	if err := os.WriteFile(configPath, []byte(legacyContent), 0644); err != nil {
		t.Fatalf("Failed to write legacy config file: %v", err)
	}

	// Test that it loads as legacy format
	_, config, err := loadFullConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load legacy configuration: %v", err)
	}

	// Verify it's in local mode (backward compatibility)
	if config.Mode != LocalMode {
		t.Errorf("Expected LocalMode for legacy config, got %v", config.Mode)
	}

	// Test migration
	logger := NewStructuredLogger(nil)
	manager := NewConfigMigrationManager(logger)

	// Check if migration is needed
	needsMigration, targetVersion, err := manager.NeedsMigration(configPath)
	if err != nil {
		t.Fatalf("Failed to check migration status: %v", err)
	}
	if !needsMigration {
		t.Error("Legacy config should need migration")
	}
	if targetVersion != "v1.0" {
		t.Errorf("Expected target version v1.0, got %s", targetVersion)
	}

	// Perform migration
	err = manager.MigrateConfig(configPath)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify migration result
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read migrated config: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "mode=local") {
		t.Error("Migrated config should contain mode=local")
	}
	if !strings.Contains(contentStr, "3000") {
		t.Error("Migrated config should preserve original ports")
	}

	// Verify the migrated config can be loaded and validated
	migratedPorts, migratedConfig, err := loadFullConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load migrated configuration: %v", err)
	}

	// Verify ports are preserved
	expectedPorts := []int{3000, 8080, 5173, 9000}
	if len(migratedPorts) != len(expectedPorts) {
		t.Errorf("Expected %d ports after migration, got %d", len(expectedPorts), len(migratedPorts))
	}

	// Verify it's still in local mode
	if migratedConfig.Mode != LocalMode {
		t.Errorf("Expected LocalMode after migration, got %v", migratedConfig.Mode)
	}

	// Verify backup was created
	backupFiles, err := filepath.Glob(configPath + ".backup.*")
	if err != nil {
		t.Errorf("Failed to check for backup files: %v", err)
	}
	if len(backupFiles) == 0 {
		t.Error("Migration should create a backup file")
	}

	t.Logf("Successfully migrated legacy configuration:")
	t.Logf("  Original ports preserved: %v", migratedPorts)
	t.Logf("  Mode set to: %s", migratedConfig.Mode.String())
	t.Logf("  Backup created: %v", backupFiles)
}
