# Technology Stack

## Language & Runtime
- **Go 1.24.5**: Primary language with modern Go features
- **Standard Library**: Heavy reliance on Go stdlib (net/http, os, log, regexp, etc.)
- **No External Dependencies**: Single binary approach with zero third-party packages

## Build System
- **Go Modules**: Standard Go module system (`go.mod`)
- **Native Go Build**: `go build -o port-redirect-service`
- **Docker Support**: Multi-stage Dockerfile with golang:bookworm base

## Common Commands
```bash
# Build
go build -o port-redirect-service

# Test
go test ./...

# Install (after build)
sudo ./install.sh install

# Service Management
sudo ./install.sh status|start|stop|restart

# Docker Build
docker build -t port-redirect-service .
```

## Platform Integration
- **macOS**: launchd service management with plist files
- **Linux**: systemd service management with service files
- **Cross-Platform Scripts**: Unified installer with platform detection

## Configuration Management
- **File-based Config**: `/etc/port-redirect/config.txt`
- **Hot Reload**: File watcher with automatic configuration updates
- **Format**: Simple text format with comments and key=value pairs

## Logging & Monitoring
- **Structured Logging**: Custom structured logger with operation-based categorization
- **Log Rotation**: Built-in log file management with size-based rotation
- **Metrics**: Web service metrics tracking (requests, redirects, rate limits)
- **Health Checks**: Dedicated health endpoint for monitoring

## Deployment
- **Fly.io**: Primary deployment platform with fly.toml configuration
- **Docker**: Containerized deployment support
- **System Services**: Native OS service integration (launchd/systemd)