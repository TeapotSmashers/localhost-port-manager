# Requirements Document

## Introduction

A lightweight Go service that runs as a system daemon on developer machines to automatically redirect domain requests with port numbers to localhost. When a developer types `3000.ai` in their browser, the service intercepts the request and redirects it to `localhost:3000`, eliminating the need to manually type localhost URLs during development.

## Requirements

### Requirement 1

**User Story:** As a developer, I want to type port-based domains like `3000.ai` in my browser, so that I can quickly access my local development servers without typing `localhost:3000`.

#### Acceptance Criteria

1. WHEN a HTTP request is received with Host header format `<port>.<tld>` THEN the system SHALL extract the port number from the host
2. WHEN a valid port number is extracted THEN the system SHALL send a HTTP 301 permanent redirect to `localhost:<port>`
3. WHEN the host header does not match the expected format THEN the system SHALL return a 404 Not Found response
4. WHEN the extracted port is not a valid number (1-65535) THEN the system SHALL return a 400 Bad Request response

### Requirement 2

**User Story:** As a developer, I want to configure which ports the service should handle through a simple text file, so that I can easily add or remove ports without restarting the service manually.

#### Acceptance Criteria

1. WHEN the service starts THEN it SHALL read a configuration file containing port numbers (one per line)
2. WHEN the configuration file is missing THEN the system SHALL create a default config with common ports (3000, 8080, 5173)
3. WHEN the configuration file is updated THEN the system SHALL detect changes and update `/etc/hosts` accordingly
4. WHEN a port is added to config THEN the system SHALL add corresponding entries to `/etc/hosts`
5. WHEN a port is removed from config THEN the system SHALL remove corresponding entries from `/etc/hosts`

### Requirement 3

**User Story:** As a developer, I want the service to automatically manage my `/etc/hosts` file based on the configuration, so that domain requests are routed to the local service without manual configuration.

#### Acceptance Criteria

1. WHEN the service starts THEN it SHALL add entries to `/etc/hosts` for each configured port pointing to localhost
2. WHEN the service stops THEN it SHALL clean up the entries it added to `/etc/hosts`
3. WHEN modifying `/etc/hosts` THEN the system SHALL create a backup of the original file
4. WHEN `/etc/hosts` modification fails THEN the system SHALL log the error and continue running without hosts file management
5. IF the service crashes THEN it SHALL have a cleanup mechanism to restore `/etc/hosts` on next startup

### Requirement 4

**User Story:** As a developer, I want to view the service status and configuration through a web interface, so that I can verify the service is working correctly and see which ports are configured.

#### Acceptance Criteria

1. WHEN accessing `/status` endpoint THEN the system SHALL display the current configuration file contents
2. WHEN accessing `/status` endpoint THEN the system SHALL show whether `/etc/hosts` file is correctly updated
3. WHEN accessing `/status` endpoint THEN the system SHALL display service uptime and last configuration reload time
4. WHEN `/etc/hosts` entries are missing or incorrect THEN the status page SHALL highlight the discrepancies
5. WHEN the configuration file has invalid entries THEN the status page SHALL show validation errors

### Requirement 5

**User Story:** As a developer, I want the service to run as a system service on both macOS and Linux, so that it starts automatically and requires no daily maintenance.

#### Acceptance Criteria

1. WHEN installed on macOS THEN the system SHALL create a launchd plist file for automatic startup
2. WHEN installed on Linux THEN the system SHALL create a systemd service file for automatic startup
3. WHEN the system boots THEN the service SHALL start automatically and bind to port 80
4. WHEN the service fails to bind to port 80 THEN it SHALL log an error and exit gracefully
5. IF the service is already running THEN a new instance SHALL detect this and exit without error

### Requirement 6

**User Story:** As a developer, I want the service to handle common development domains, so that I can use intuitive URLs for my local services.

#### Acceptance Criteria

1. WHEN a request comes for `*.local`, `*.dev`, `*.test`, or `*.localhost` domains THEN the system SHALL process the port extraction
2. WHEN a request comes for other TLDs THEN the system SHALL still process them if they match the port pattern
3. WHEN multiple developers use the same machine THEN the system SHALL work for all users simultaneously
4. WHEN the service receives requests on non-port-based domains THEN it SHALL return a helpful error message

### Requirement 7

**User Story:** As a developer, I want proper logging and error handling, so that I can troubleshoot issues when the service doesn't work as expected.

#### Acceptance Criteria

1. WHEN the service starts THEN it SHALL log the startup status and listening port
2. WHEN a redirect occurs THEN the system SHALL log the original host and redirect target
3. WHEN an error occurs THEN the system SHALL log detailed error information with timestamps
4. WHEN the service stops THEN it SHALL log the shutdown process and cleanup actions
5. IF running with insufficient privileges THEN the system SHALL provide clear error messages about required permissions

### Requirement 8

**User Story:** As a developer, I want easy installation and uninstallation with clear documentation, so that I can set up or remove the service without complex manual steps.

#### Acceptance Criteria

1. WHEN installing the service THEN the system SHALL provide a single command or script for installation
2. WHEN uninstalling THEN the system SHALL remove all created files and restore original system state
3. WHEN installation requires sudo privileges THEN the system SHALL clearly prompt for and explain why privileges are needed
4. WHEN installation fails THEN the system SHALL provide clear error messages and rollback any partial changes
5. IF the service is already installed THEN reinstallation SHALL update the existing installation safely
6. WHEN reading the README THEN it SHALL include step-by-step installation instructions for both macOS and Linux
7. WHEN reading the README THEN it SHALL include service management commands (start, stop, restart, status) for both platforms