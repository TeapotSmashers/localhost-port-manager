# Implementation Plan

- [x] 1. Set up project structure and core types
  - Create Go module with main.go and package structure
  - Define core service structs and interfaces using only standard library
  - Create basic configuration struct for ports and file paths
  - _Requirements: 1.1, 2.1, 3.1_

- [x] 2. Implement configuration management
  - [x] 2.1 Create configuration file parser
    - Write function to read port numbers from text file (one per line)
    - Implement comment support (lines starting with #)
    - Add validation for port numbers (1-65535 range)
    - Create default configuration file creation logic
    - _Requirements: 2.1, 2.2, 2.3_
  
  - [x] 2.2 Add configuration file watching
    - Implement file modification detection using standard library
    - Create configuration reload mechanism
    - Add error handling for invalid configuration updates
    - _Requirements: 2.3, 2.4, 2.5_

- [x] 3. Implement HTTP request handling
  - [x] 3.1 Create port extraction logic
    - Write regex pattern to match `<port>.<tld>` format in Host header
    - Implement port number extraction and validation
    - Add support for common development TLDs (.local, .dev, .test, .localhost)
    - _Requirements: 1.1, 1.2, 6.1, 6.2_
  
  - [x] 3.2 Implement redirect handler
    - Create HTTP handler that extracts port from Host header
    - Generate HTTP 301 redirect to `localhost:<port>`
    - Add error responses for invalid hosts (404) and invalid ports (400)
    - _Requirements: 1.2, 1.3, 1.4, 6.4_

- [x] 4. Implement hosts file management
  - [x] 4.1 Create hosts file backup and restore
    - Write function to create backup of original `/etc/hosts`
    - Implement restore mechanism for cleanup
    - Add error handling for file permission issues
    - _Requirements: 3.3, 3.4, 3.5_
  
  - [x] 4.2 Implement hosts file entry management
    - Create function to add port-based entries to `/etc/hosts`
    - Implement entry removal for cleanup
    - Add logic to update entries when configuration changes
    - Use managed section markers (BEGIN/END PORT-REDIRECT-SERVICE)
    - _Requirements: 3.1, 3.2, 2.4, 2.5_

- [x] 5. Create status web interface
  - [x] 5.1 Implement status data collection
    - Create struct to hold service status information
    - Implement functions to check hosts file validity
    - Add configuration validation and error reporting
    - Track service uptime and last configuration reload
    - _Requirements: 4.1, 4.2, 4.3, 4.5_
  
  - [x] 5.2 Create status page handler
    - Write HTTP handler for `/status` endpoint
    - Generate HTML page showing configuration and status
    - Display hosts file validation results and discrepancies
    - Add JSON API endpoint for programmatic access
    - _Requirements: 4.1, 4.2, 4.4_

- [x] 6. Implement main HTTP server
  - [x] 6.1 Create HTTP server setup
    - Initialize HTTP server on port 80 using standard library
    - Register redirect handler for all requests except `/status`
    - Add graceful shutdown handling with signal catching
    - Implement error handling for port binding failures
    - _Requirements: 5.3, 5.4, 7.1, 7.2_
  
  - [x] 6.2 Add logging and error handling
    - Implement structured logging for all operations
    - Log redirect operations with source and target
    - Add startup, shutdown, and error logging
    - Create log rotation or size management
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [x] 7. Create service lifecycle management
  - [x] 7.1 Implement service startup logic
    - Create main function that initializes all components
    - Add configuration loading and hosts file setup
    - Implement service detection to prevent multiple instances
    - Add privilege checking and clear error messages
    - _Requirements: 5.1, 5.2, 5.5, 7.5_
  
  - [x] 7.2 Implement graceful shutdown
    - Add signal handlers for SIGTERM and SIGINT
    - Implement cleanup of hosts file entries on shutdown
    - Ensure proper resource cleanup and logging
    - _Requirements: 3.2, 3.5, 7.4_

- [x] 8. Create cross-platform service installation
  - [x] 8.1 Implement macOS launchd integration
    - Create launchd plist file template
    - Write installation script for macOS service registration
    - Add service management commands (start, stop, restart)
    - _Requirements: 5.1, 8.1, 8.6, 8.7_
  
  - [x] 8.2 Implement Linux systemd integration
    - Create systemd service file template
    - Write installation script for systemd service registration
    - Add service management commands using systemctl
    - _Requirements: 5.2, 8.1, 8.6, 8.7_
  
  - [x] 8.3 Create unified installation script
    - Write platform detection logic
    - Create single installation script that works on both platforms
    - Add uninstallation functionality with complete cleanup
    - Implement installation validation and rollback on failure
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

- [ ] 9. Create comprehensive documentation
  - [ ] 9.1 Write README with installation instructions
    - Document installation process for both macOS and Linux
    - Include service management commands for both platforms
    - Add configuration file format and examples
    - Document troubleshooting steps and common issues
    - _Requirements: 8.6, 8.7_
  
  - [ ] 9.2 Add usage examples and configuration guide
    - Create examples of common port configurations
    - Document status page usage and interpretation
    - Add security considerations and permission requirements
    - Include uninstallation instructions
    - _Requirements: 8.6, 8.7_

- [ ] 10. Implement comprehensive testing
  - [ ] 10.1 Create unit tests for core functionality
    - Write tests for configuration parsing and validation
    - Test port extraction regex patterns
    - Test hosts file management with temporary files
    - Test HTTP handlers with httptest package
    - _Requirements: All requirements validation_
  
  - [ ] 10.2 Create integration tests
    - Write end-to-end tests for redirect flow
    - Test configuration reload functionality
    - Test service lifecycle (startup/shutdown)
    - Add platform-specific service installation tests
    - _Requirements: All requirements validation_