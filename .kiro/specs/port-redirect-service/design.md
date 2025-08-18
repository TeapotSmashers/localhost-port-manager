# Design Document

## Overview

The Port Redirect Service is a lightweight Go daemon that intercepts HTTP requests for port-based domains (e.g., `3000.ai`) and redirects them to `localhost:<port>`. The service is built using only Go's standard library to maintain simplicity and minimize dependencies. It manages `/etc/hosts` entries based on a configuration file and provides a web-based status interface for monitoring.

### Design Principles

- **Minimal Dependencies**: Uses only Go standard library (`net/http`, `os`, `regexp`, `log`, etc.)
- **Lightweight**: Single binary with minimal resource footprint
- **Cross-Platform**: Works on both macOS and Linux with platform-specific service integration
- **Zero Configuration**: Works out of the box with sensible defaults

## Architecture

### High-Level Architecture

```
Browser Request (3000.ai) 
    ↓
/etc/hosts (points to localhost:80)
    ↓
Port Redirect Service (localhost:80)
    ↓
HTTP 301 Redirect (localhost:3000)
    ↓
Developer's Local Server (localhost:3000)
```

### System Components

1. **HTTP Server**: Handles incoming requests and performs redirects
2. **Configuration Manager**: Reads and monitors port configuration file
3. **Hosts File Manager**: Manages `/etc/hosts` entries with backup/restore
4. **Status Web Interface**: Provides service status and configuration view
5. **System Service Integration**: Platform-specific service installation

## Components and Interfaces

### Core Service Structure

```go
type PortRedirectService struct {
    server          *http.Server
    config          *Config
    hostsManager    *HostsManager
    configWatcher   *fsnotify.Watcher
    logger          *log.Logger
}

type Config struct {
    Ports           []int
    ConfigFilePath  string
    HostsBackupPath string
    LogLevel        string
}

type HostsManager struct {
    hostsFilePath   string
    backupPath      string
    managedEntries  []string
}
```

### HTTP Handler Interface

```go
type Handler interface {
    ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// Main redirect handler
func (s *PortRedirectService) handleRedirect(w http.ResponseWriter, r *http.Request)

// Status page handler  
func (s *PortRedirectService) handleStatus(w http.ResponseWriter, r *http.Request)
```

### Dependencies

**Standard Library Only:**
- `net/http` - HTTP server and client functionality
- `os` - File system operations and signal handling
- `regexp` - Pattern matching for host header parsing
- `log` - Logging functionality
- `time` - Time operations and timers
- `strings` - String manipulation
- `strconv` - String to integer conversion
- `bufio` - Buffered I/O for file operations
- `path/filepath` - Cross-platform file path handling

**No External Dependencies** - The service is designed to compile and run with zero external Go modules.

### Configuration File Format

```
# Port Redirect Service Configuration
# One port per line, comments start with #

3000
8080
5173
9000
```

### Hosts File Management

The service will add entries like:
```
# BEGIN PORT-REDIRECT-SERVICE
3000.local 127.0.0.1
3000.dev 127.0.0.1
3000.test 127.0.0.1
8080.local 127.0.0.1
8080.dev 127.0.0.1
8080.test 127.0.0.1
# END PORT-REDIRECT-SERVICE
```

## Data Models

### Configuration Model

```go
type ServiceConfig struct {
    Ports           []int     `json:"ports"`
    LastModified    time.Time `json:"last_modified"`
    ConfigPath      string    `json:"config_path"`
    HostsPath       string    `json:"hosts_path"`
    BackupPath      string    `json:"backup_path"`
}
```

### Status Model

```go
type ServiceStatus struct {
    Uptime          time.Duration     `json:"uptime"`
    ConfigLoaded    time.Time         `json:"config_loaded"`
    PortsConfigured []int             `json:"ports_configured"`
    HostsStatus     HostsFileStatus   `json:"hosts_status"`
    LastError       string            `json:"last_error,omitempty"`
}

type HostsFileStatus struct {
    BackupExists    bool              `json:"backup_exists"`
    EntriesValid    bool              `json:"entries_valid"`
    MissingEntries  []string          `json:"missing_entries,omitempty"`
    ExtraEntries    []string          `json:"extra_entries,omitempty"`
}
```

## Error Handling

### Error Categories

1. **Configuration Errors**: Invalid port numbers, file permissions
2. **Network Errors**: Port 80 binding failures, request handling errors  
3. **System Errors**: `/etc/hosts` modification failures, service installation errors
4. **Runtime Errors**: File watching failures, graceful shutdown issues

### Error Handling Strategy

```go
type ServiceError struct {
    Type        ErrorType
    Message     string
    Underlying  error
    Timestamp   time.Time
    Recoverable bool
}

type ErrorType int

const (
    ConfigError ErrorType = iota
    NetworkError
    SystemError
    RuntimeError
)
```

### Recovery Mechanisms

- **Configuration errors**: Continue with last known good config
- **Hosts file errors**: Log error but continue serving redirects
- **Port binding errors**: Exit gracefully with clear error message
- **File watching errors**: Fall back to periodic config reload

## Testing Strategy

### Unit Tests

1. **Configuration parsing**: Test valid/invalid config files
2. **Port extraction**: Test regex patterns for various domain formats
3. **Hosts file management**: Test entry addition/removal with mocked filesystem
4. **HTTP handlers**: Test redirect logic and status page rendering

### Integration Tests

1. **End-to-end redirect flow**: Test actual HTTP requests and redirects
2. **Configuration reload**: Test file watching and dynamic reconfiguration
3. **Hosts file integration**: Test actual `/etc/hosts` modification (with cleanup)
4. **Service lifecycle**: Test startup, shutdown, and cleanup procedures

### Platform-Specific Tests

1. **macOS launchd integration**: Test plist generation and service registration
2. **Linux systemd integration**: Test service file generation and systemctl commands
3. **Cross-platform file paths**: Test config and hosts file path resolution

### Test Environment Setup

```go
type TestEnvironment struct {
    TempDir        string
    MockHostsFile  string
    MockConfigFile string
    TestServer     *httptest.Server
}
```

## Platform-Specific Implementation

### macOS (launchd)

**Service File**: `/Library/LaunchDaemons/com.portredirect.service.plist`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.portredirect.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/port-redirect-service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

### Linux (systemd)

**Service File**: `/etc/systemd/system/port-redirect.service`

```ini
[Unit]
Description=Port Redirect Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/port-redirect-service
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

## Security Considerations

### Permission Requirements

**Root/Administrator Access Required For:**
1. **Port 80 Binding**: Only root can bind to privileged ports (< 1024) on Unix systems
2. **`/etc/hosts` Modification**: System hosts file requires root write permissions
3. **System Service Installation**: Installing launchd/systemd services requires elevated privileges

**Security Measures:**
1. **Input Validation**: Strict validation of host headers and port numbers using regex
2. **File Permissions**: Secure handling of configuration and hosts files with proper ownership
3. **Minimal Attack Surface**: No external dependencies, simple HTTP handlers only
4. **Graceful Degradation**: Continue operating even if hosts file modification fails

**Installation Security:**
- Installation script validates file integrity before copying binaries
- Service files are created with restrictive permissions (644 for config, 755 for binary)
- Backup files are created before modifying system files

## Performance Considerations

1. **Memory Usage**: Minimal footprint with efficient string processing
2. **Request Latency**: Fast regex matching and immediate redirects
3. **File I/O**: Efficient hosts file management with minimal disk operations
4. **Concurrent Requests**: Go's built-in HTTP server handles concurrency

## Deployment and Installation

### Installation Script Structure

```bash
#!/bin/bash
# install.sh

detect_platform() {
    # Detect macOS vs Linux
}

install_binary() {
    # Copy binary to /usr/local/bin
}

create_config() {
    # Create default configuration file
}

setup_service() {
    # Platform-specific service setup
}

update_hosts() {
    # Initial hosts file setup
}
```

### Directory Structure

```
/usr/local/bin/port-redirect-service          # Main binary
/etc/port-redirect/config.txt                 # Configuration file
/etc/port-redirect/hosts.backup               # Hosts file backup
/var/log/port-redirect.log                    # Log file (Linux)
~/Library/Logs/port-redirect.log              # Log file (macOS)
```