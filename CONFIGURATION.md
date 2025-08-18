# Configuration Reference

This document provides a comprehensive reference for configuring the Port Redirect Service in both Local Mode and Web Service Mode.

## Table of Contents

- [Configuration File Format](#configuration-file-format)
- [Local Mode Configuration](#local-mode-configuration)
- [Web Service Mode Configuration](#web-service-mode-configuration)
- [Configuration Parameters](#configuration-parameters)
- [Domain Pattern Examples](#domain-pattern-examples)
- [Configuration Validation](#configuration-validation)
- [Migration Guide](#migration-guide)

## Configuration File Format

The service reads configuration from `/etc/port-redirect/config.txt`. The file supports:

- **Port numbers**: One per line (1-65535)
- **Comments**: Lines starting with `#`
- **Empty lines**: Ignored for readability
- **Key-value pairs**: For mode-specific settings

### Basic Format
```bash
# Port Redirect Service Configuration
# Comments start with #

# Port numbers (one per line)
3000
8080
5173

# Configuration parameters (key=value format)
mode=web
web_port=8080
domain_patterns=*.example.com
```

## Local Mode Configuration

Local Mode is the default deployment mode. It requires minimal configuration.

### Minimal Local Mode Configuration
```bash
# /etc/port-redirect/config.txt
# Minimal local mode configuration

3000
8080
5173
```

### Explicit Local Mode Configuration
```bash
# /etc/port-redirect/config.txt
# Explicit local mode configuration

# Development ports
3000    # React development server
8080    # Backend API server
5173    # Vite development server
4200    # Angular CLI server

# Explicitly set local mode (optional)
mode=local
```

### Local Mode Features
- Automatically modifies `/etc/hosts` file
- Listens on port 80 (requires root privileges)
- Supports domains: `<port>.local`, `<port>.dev`, `<port>.test`, `<port>.localhost`
- No additional configuration required

## Web Service Mode Configuration

Web Service Mode requires additional configuration for domain patterns and service settings.

### Basic Web Service Configuration
```bash
# /etc/port-redirect/config.txt
# Basic web service configuration

# Port numbers
3000
8080
5173

# Web service mode
mode=web
web_port=8080
domain_patterns=*.yourdomain.com
```

### Complete Web Service Configuration
```bash
# /etc/port-redirect/config.txt
# Complete web service configuration

# Application ports
3000    # Frontend application
8000    # Main API server
8001    # Authentication service
8002    # File upload service
5173    # Development tools

# Web service mode settings
mode=web
web_port=8080
domain_patterns=*.sankalpmukim.dev,*.example.com,*.dev.local

# Security and performance settings
enable_rate_limit=true
rate_limit_rps=100
```

### Production Web Service Configuration
```bash
# /etc/port-redirect/config.txt
# Production web service configuration

# Production ports
3000    # Production frontend
8000    # Production API

# Web service mode
mode=web
web_port=80
domain_patterns=*.company.com

# Enhanced security for production
enable_rate_limit=true
rate_limit_rps=50
```

## Configuration Parameters

### Common Parameters

#### Port Numbers
- **Format**: One port number per line
- **Range**: 1-65535
- **Example**:
  ```bash
  3000
  8080
  5173
  ```

#### Comments
- **Format**: Lines starting with `#`
- **Usage**: Documentation and temporary disabling
- **Example**:
  ```bash
  # This is a comment
  3000    # React development server
  # 8080  # Temporarily disabled
  ```

### Local Mode Parameters

#### mode (Optional)
- **Values**: `local`
- **Default**: `local` (if not specified)
- **Example**: `mode=local`

### Web Service Mode Parameters

#### mode (Required)
- **Values**: `web`, `webservice`, `web-service`
- **Required**: Yes (for web service mode)
- **Example**: `mode=web`

#### web_port (Optional)
- **Values**: 1-65535
- **Default**: 8080
- **Description**: Port for the web service to listen on
- **Example**: `web_port=8080`

#### domain_patterns (Required for Web Mode)
- **Format**: Comma-separated list of domain patterns
- **Wildcards**: Supported with `*` prefix
- **Required**: Yes (for web service mode)
- **Example**: `domain_patterns=*.example.com,*.dev.local`

#### enable_rate_limit (Optional)
- **Values**: `true`, `false`
- **Default**: `false`
- **Description**: Enable per-IP rate limiting
- **Example**: `enable_rate_limit=true`

#### rate_limit_rps (Optional)
- **Values**: Positive integer
- **Default**: 100
- **Description**: Requests per second limit per IP
- **Example**: `rate_limit_rps=100`

## Domain Pattern Examples

### Single Domain Pattern
```bash
# Single domain with wildcard
domain_patterns=*.sankalpmukim.dev

# Matches:
# 3000.sankalpmukim.dev
# 8080.sankalpmukim.dev
# 5173.sankalpmukim.dev
```

### Multiple Domain Patterns
```bash
# Multiple domains
domain_patterns=*.example.com,*.dev.local,*.staging.company.com

# Matches:
# 3000.example.com
# 8080.dev.local  
# 5173.staging.company.com
```

### Environment-Specific Patterns
```bash
# Development environment
domain_patterns=*.dev.company.com

# Staging environment  
domain_patterns=*.staging.company.com

# Production environment
domain_patterns=*.company.com
```

### Complex Pattern Examples
```bash
# Multi-environment setup
domain_patterns=*.dev.company.com,*.test.company.com,*.demo.company.com

# Different TLDs
domain_patterns=*.example.com,*.example.org,*.example.net

# Subdomain variations
domain_patterns=*.api.company.com,*.app.company.com,*.admin.company.com
```

## Configuration Validation

### Automatic Validation

The service automatically validates configuration on startup and reload:

```bash
# Check service status for validation errors
sudo ./install.sh status

# View validation errors in logs
# macOS:
tail -f /var/log/port-redirect-service.log | grep ERROR

# Linux:
journalctl -u port-redirect -f | grep ERROR
```

### Manual Validation

#### Port Number Validation
```bash
# Check for invalid port numbers
awk '/^[0-9]+$/ { 
    if ($1 < 1 || $1 > 65535) 
        print "Invalid port: " $1 
}' /etc/port-redirect/config.txt
```

#### Configuration Format Validation
```bash
# Check configuration format
grep -E "^[0-9]+$|^[a-z_]+=|^#|^$" /etc/port-redirect/config.txt

# Check for required web service parameters
if grep -q "mode=web" /etc/port-redirect/config.txt; then
    if ! grep -q "domain_patterns=" /etc/port-redirect/config.txt; then
        echo "ERROR: domain_patterns required for web service mode"
    fi
fi
```

#### Domain Pattern Validation
```bash
# Test domain pattern matching (requires service to be running)
curl -I -H "Host: 3000.yourdomain.com" http://localhost:8080

# Check pattern configuration
grep "domain_patterns=" /etc/port-redirect/config.txt
```

### Common Validation Errors

#### Invalid Port Numbers
```bash
# Error: Port out of range
70000    # Invalid: > 65535
0        # Invalid: < 1
-1       # Invalid: negative
```

#### Missing Required Parameters
```bash
# Error: Web mode without domain patterns
mode=web
web_port=8080
# Missing: domain_patterns=*.example.com
```

#### Invalid Domain Patterns
```bash
# Error: Empty domain pattern
domain_patterns=

# Error: Invalid pattern format
domain_patterns=*.
domain_patterns=*
```

## Migration Guide

### Upgrading from Local Mode to Web Service Mode

1. **Backup current configuration:**
   ```bash
   sudo cp /etc/port-redirect/config.txt /etc/port-redirect/config.txt.backup
   ```

2. **Add web service parameters:**
   ```bash
   sudo tee -a /etc/port-redirect/config.txt << EOF
   
   # Web service mode
   mode=web
   web_port=8080
   domain_patterns=*.yourdomain.com
   EOF
   ```

3. **Restart service:**
   ```bash
   sudo ./install.sh restart
   ```

4. **Verify web service mode:**
   ```bash
   curl http://localhost:8080/status | grep "Deployment Mode"
   ```

### Downgrading from Web Service Mode to Local Mode

1. **Backup current configuration:**
   ```bash
   sudo cp /etc/port-redirect/config.txt /etc/port-redirect/config.txt.backup
   ```

2. **Remove web service parameters:**
   ```bash
   sudo sed -i '/^mode=web/d' /etc/port-redirect/config.txt
   sudo sed -i '/^web_port=/d' /etc/port-redirect/config.txt
   sudo sed -i '/^domain_patterns=/d' /etc/port-redirect/config.txt
   sudo sed -i '/^enable_rate_limit=/d' /etc/port-redirect/config.txt
   sudo sed -i '/^rate_limit_rps=/d' /etc/port-redirect/config.txt
   ```

3. **Restart service:**
   ```bash
   sudo ./install.sh restart
   ```

4. **Verify local mode:**
   ```bash
   curl http://localhost/status | grep "Deployment Mode"
   ```

### Configuration Version Migration

#### Legacy Format (v0.x)
```bash
# Old format (ports only)
3000
8080
5173
```

#### Current Format (v1.x)
```bash
# New format (ports + configuration)
3000
8080
5173

mode=web
web_port=8080
domain_patterns=*.example.com
```

The service automatically detects and supports both formats for backward compatibility.

## Configuration Templates

### Development Team Template
```bash
# /etc/port-redirect/config.txt
# Development team configuration template

# Frontend applications
3000    # Main application
3001    # Admin interface
3002    # Mobile web app

# Backend services
8000    # Main API
8001    # Authentication service
8002    # File service

# Development tools
9000    # Documentation site
9001    # Monitoring dashboard
9002    # Testing tools

# Web service mode for team access
mode=web
web_port=8080
domain_patterns=*.dev.company.com

# Moderate rate limiting for team use
enable_rate_limit=true
rate_limit_rps=200
```

### Microservices Template
```bash
# /etc/port-redirect/config.txt
# Microservices architecture template

# API Gateway
8000

# Core services
8001    # User service
8002    # Product service
8003    # Order service
8004    # Payment service
8005    # Notification service

# Frontend applications
3000    # Customer portal
3001    # Admin dashboard
3002    # Mobile app

# Infrastructure
9090    # Prometheus
3001    # Grafana
5601    # Kibana

# Web service mode
mode=web
web_port=80
domain_patterns=*.api.company.com,*.app.company.com

# Production-grade rate limiting
enable_rate_limit=true
rate_limit_rps=100
```

### Multi-Environment Template
```bash
# /etc/port-redirect/config.txt
# Multi-environment configuration template

# Development environment
3000    # Dev frontend
8000    # Dev API

# Staging environment
3100    # Staging frontend
8100    # Staging API

# Production environment
3200    # Prod frontend
8200    # Prod API

# Web service mode with environment-specific domains
mode=web
web_port=8080
domain_patterns=*.dev.company.com,*.staging.company.com,*.prod.company.com

# Environment-appropriate rate limiting
enable_rate_limit=true
rate_limit_rps=150
```

This configuration reference provides comprehensive documentation for all configuration options and scenarios supported by the Port Redirect Service.