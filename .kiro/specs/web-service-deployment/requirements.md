# Requirements Document

## Introduction

This feature extends the existing port redirect service to operate as a deployed web service that handles subdomain-based redirects. The service will accept requests from domains like `3000.sankalpmukim.dev` and `8080.sankalpmukim.dev` and redirect them to the appropriate localhost ports. This enables remote access to local development servers through a centralized redirect service while maintaining the existing local functionality.

## Requirements

### Requirement 1

**User Story:** As a developer, I want to access my local development servers through public subdomains, so that I can share my work with others or access it from different devices.

#### Acceptance Criteria

1. WHEN a request is made to `<port>.sankalpmukim.dev` THEN the system SHALL redirect to `localhost:<port>` with HTTP 301 status
2. WHEN the port number is valid (1-65535) THEN the system SHALL process the redirect request
3. WHEN the port number is invalid THEN the system SHALL return HTTP 400 Bad Request
4. WHEN the subdomain format is incorrect THEN the system SHALL return HTTP 404 Not Found

### Requirement 2

**User Story:** As a developer, I want the service to work both locally and as a deployed web service, so that I can use the same codebase for different deployment scenarios.

#### Acceptance Criteria

1. WHEN running in local mode THEN the system SHALL modify `/etc/hosts` and listen on port 80
2. WHEN running in web service mode THEN the system SHALL listen on a configurable port without modifying system files
3. WHEN the deployment mode is specified via configuration THEN the system SHALL adapt its behavior accordingly
4. WHEN no mode is specified THEN the system SHALL default to local mode for backward compatibility

### Requirement 3

**User Story:** As a system administrator, I want to configure the web service deployment settings, so that I can customize the domain, port, and other deployment parameters.

#### Acceptance Criteria

1. WHEN a configuration file specifies web service mode THEN the system SHALL use the provided domain pattern
2. WHEN a custom port is specified for web service mode THEN the system SHALL listen on that port
3. WHEN domain patterns are configured THEN the system SHALL validate requests against those patterns
4. WHEN configuration is invalid THEN the system SHALL log errors and use safe defaults

### Requirement 4

**User Story:** As a developer, I want the web service to support multiple domain patterns, so that I can use different domains for different environments or purposes.

#### Acceptance Criteria

1. WHEN multiple domain patterns are configured THEN the system SHALL accept requests matching any pattern
2. WHEN a request matches `<port>.<configured-domain>` THEN the system SHALL extract the port and redirect
3. WHEN domain patterns include wildcards THEN the system SHALL validate them properly
4. WHEN no domain patterns are configured in web mode THEN the system SHALL return an error

### Requirement 5

**User Story:** As a developer, I want the web service to maintain security best practices, so that the redirect service cannot be abused for malicious purposes.

#### Acceptance Criteria

1. WHEN processing redirect requests THEN the system SHALL only redirect to localhost addresses
2. WHEN validating port numbers THEN the system SHALL enforce the valid range (1-65535)
3. WHEN receiving malformed requests THEN the system SHALL log them and return appropriate error responses
4. WHEN rate limiting is enabled THEN the system SHALL prevent abuse from excessive requests

### Requirement 6

**User Story:** As a developer, I want comprehensive logging and monitoring for the web service, so that I can troubleshoot issues and monitor usage.

#### Acceptance Criteria

1. WHEN processing requests THEN the system SHALL log request details including source IP and target port
2. WHEN errors occur THEN the system SHALL log detailed error information
3. WHEN the service starts THEN the system SHALL log the deployment mode and configuration
4. WHEN providing status information THEN the system SHALL include web service specific metrics