# Project Structure

## Root Directory
- **main.go**: Single-file application with all core functionality (~4000 lines)
- **go.mod**: Go module definition with Go 1.24.5
- **Dockerfile**: Multi-stage Docker build configuration
- **install.sh**: Unified cross-platform installer script

## Documentation
- **README.md**: Comprehensive user documentation with examples
- **CONFIGURATION.md**: Detailed configuration reference
- **DEPLOYMENT.md**: Deployment guide for both modes
- **INSTALL.md**: Installation instructions
- **USAGE.md**: Usage examples and workflows
- **SECURITY.md**: Security considerations and best practices

## Platform-Specific Scripts
```
scripts/
├── linux/
│   ├── install.sh              # Linux systemd installer
│   └── port-redirect.service   # systemd service file
└── macos/
    ├── install.sh              # macOS launchd installer
    └── com.portredirect.service.plist  # launchd plist
```

## Test Files
All test files follow `*_test.go` naming convention:
- **main_test.go**: Core functionality tests
- **integration_test.go**: End-to-end integration tests
- **enhanced_status_test.go**: Status endpoint tests
- **rate_limiter_test.go**: Rate limiting functionality tests
- **domain_matcher_test.go**: Domain pattern matching tests
- **config_watcher_test.go**: Configuration watching tests
- **mode_aware_handler_test.go**: Handler system tests
- **security_validation_test.go**: Security validation tests
- **web_service_initialization_test.go**: Web service tests

## Configuration Structure
```
/etc/port-redirect/
├── config.txt          # Main configuration file
├── hosts.backup        # Backup of original hosts file
└── *.backup.*          # Timestamped configuration backups
```

## Code Organization Patterns
- **Single File Architecture**: All code in main.go with clear struct separation
- **Interface-Based Design**: DomainMatcher, RateLimiter interfaces for extensibility
- **Mode-Aware Components**: Handlers switch behavior based on deployment mode
- **Comprehensive Error Types**: Custom error types for different failure scenarios
- **Test Environment Helpers**: Reusable test environment setup functions

## Naming Conventions
- **Structs**: PascalCase (e.g., `PortRedirectService`, `HostsManager`)
- **Functions**: PascalCase for exported, camelCase for internal
- **Constants**: PascalCase with descriptive prefixes
- **Test Functions**: `Test` prefix with descriptive names
- **Files**: snake_case for test files, kebab-case for scripts