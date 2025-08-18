# Implementation Plan

- [x] 1. Create deployment mode configuration system
  - Implement DeploymentMode enum and configuration structures
  - Add configuration parsing for mode detection and web service parameters
  - Create validation functions for deployment-specific configuration
  - Write unit tests for configuration loading and validation
  - _Requirements: 2.3, 3.1, 3.4_

- [x] 2. Implement domain pattern matching system
  - Create DomainMatcher interface and PatternMatcher implementation
  - Add regex-based pattern compilation and validation
  - Implement port extraction from subdomain format for web service mode
  - Write unit tests for pattern matching and port extraction
  - _Requirements: 1.1, 4.1, 4.2, 4.3_

- [x] 3. Extend configuration file format and parsing
  - Modify configuration file parser to support mode and web service parameters
  - Add backward compatibility for existing configuration files
  - Implement configuration validation for both local and web service modes
  - Create configuration migration utilities for existing installations
  - Write unit tests for enhanced configuration parsing
  - _Requirements: 2.3, 3.1, 3.2, 3.4_

- [x] 4. Create mode-aware request handler system
  - Implement ModeAwareHandler that routes requests based on deployment mode
  - Create WebServiceHandler for web service specific request processing
  - Modify existing redirect logic to work with both local and web service modes
  - Add request validation for host header format and domain patterns
  - Write unit tests for mode-aware request routing
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2_

- [x] 5. Implement enhanced port extraction and validation
  - Extend extractPortFromHost function to support web service domain patterns
  - Add domain pattern validation before port extraction
  - Implement port validation against configured port lists
  - Create error handling for invalid domains and ports
  - Write unit tests for port extraction and validation logic
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 4.2_

- [x] 6. Add web service mode initialization and server setup
  - Modify main function to detect deployment mode and initialize appropriate components
  - Implement configurable port binding for web service mode
  - Add web service specific logging and monitoring
  - Create graceful shutdown handling for both modes
  - Write integration tests for service initialization in both modes
  - _Requirements: 2.1, 2.2, 2.4, 6.3_

- [x] 7. Implement security and validation enhancements
  - Add input validation for host headers and request parameters
  - Implement localhost-only redirect validation
  - Add request logging with security-relevant information
  - Create error responses that don't leak sensitive information
  - Write security-focused unit tests for validation functions
  - _Requirements: 5.1, 5.2, 5.3, 6.1, 6.2_

- [x] 8. Add optional rate limiting system
  - Create RateLimiter interface and IPRateLimiter implementation
  - Implement per-IP request rate limiting with configurable limits
  - Add rate limiter integration to web service request handler
  - Create cleanup mechanisms for rate limiter memory management
  - Write unit tests for rate limiting functionality
  - _Requirements: 5.4_

- [x] 9. Enhance status and monitoring endpoints
  - Extend status endpoint to show deployment mode and web service metrics
  - Add web service specific status information (domain patterns, request counts)
  - Implement health check endpoint suitable for load balancers
  - Add JSON API responses for programmatic monitoring
  - Write unit tests for enhanced status endpoints
  - _Requirements: 6.4_

- [ ] 10. Add/update comprehensive documentation. 
  - It should include step by step any and all configuration required, how to control the two modes.