# Usage Guide and Configuration Examples

This guide provides detailed usage examples and configuration scenarios for the Port Redirect Service.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Configuration Examples](#configuration-examples)
- [Development Workflows](#development-workflows)
- [Status Page Guide](#status-page-guide)
- [Security Considerations](#security-considerations)
- [Advanced Configuration](#advanced-configuration)

## Basic Usage

### Getting Started

After installation, the service automatically starts and creates a default configuration:

```bash
# Check if service is running
sudo ./install.sh status

# View current configuration
cat /etc/port-redirect/config.txt

# Test a redirect
curl -I http://3000.local
```

### Typical Development Workflow

1. **Start your development server:**
   ```bash
   # Example: React development server
   npm start
   # Server starts on localhost:3000
   ```

2. **Add port to configuration:**
   ```bash
   echo "3000" | sudo tee -a /etc/port-redirect/config.txt
   ```

3. **Access via friendly URL:**
   ```bash
   # Instead of http://localhost:3000
   # Use any of these:
   open http://3000.local
   open http://3000.dev
   open http://3000.test
   ```

## Configuration Examples

### Frontend Development

```bash
# /etc/port-redirect/config.txt
# Frontend Development Ports

# React Create App
3000

# Vite Development Server
5173

# Next.js Development
3000

# Angular CLI
4200

# Vue CLI
8080

# Webpack Dev Server
8080

# Parcel
1234

# Rollup
10001
```

### Backend Development

```bash
# /etc/port-redirect/config.txt
# Backend Development Ports

# Express.js
3000
8000

# FastAPI
8000

# Django
8000

# Flask
5000

# Spring Boot
8080

# ASP.NET Core
5000
5001

# Go HTTP Server
8080

# Ruby on Rails
3000
```

### Full-Stack Development

```bash
# /etc/port-redirect/config.txt
# Full-Stack Development Setup

# Frontend
3000    # React/Vue frontend
4200    # Angular frontend

# Backend APIs
8000    # Main API server
8001    # Authentication service
8002    # Payment service

# Development Tools
3001    # Storybook
9229    # Node.js debugger
5555    # GraphQL Playground

# Database Interfaces
8080    # phpMyAdmin
8081    # Adminer
5050    # pgAdmin
```

### Microservices Development

```bash
# /etc/port-redirect/config.txt
# Microservices Architecture

# API Gateway
8000

# User Service
8001

# Product Service
8002

# Order Service
8003

# Payment Service
8004

# Notification Service
8005

# Admin Dashboard
3000

# Monitoring
9090    # Prometheus
3001    # Grafana
```

### Docker Development

```bash
# /etc/port-redirect/config.txt
# Docker Compose Services

# Web Application
8080

# API Server
3000

# Database Admin
8081

# Redis Admin
8082

# Elasticsearch
9200

# Kibana
5601

# Jaeger UI
16686
```

## Development Workflows

### React + Node.js Stack

```bash
# 1. Configure ports
cat > /tmp/config.txt << EOF
3000    # React frontend
8000    # Node.js API
3001    # Storybook
EOF
sudo cp /tmp/config.txt /etc/port-redirect/config.txt

# 2. Start services
# Terminal 1: Frontend
npm start  # Starts on :3000

# Terminal 2: Backend
node server.js  # Starts on :8000

# Terminal 3: Storybook
npm run storybook  # Starts on :3001

# 3. Access services
open http://3000.local     # Frontend
open http://8000.local     # API
open http://3001.local     # Storybook
```

### Multi-Environment Setup

```bash
# Development environment
# /etc/port-redirect/config.txt
3000    # dev-frontend
8000    # dev-api

# Testing environment (different ports)
3100    # test-frontend  
8100    # test-api

# Staging environment
3200    # staging-frontend
8200    # staging-api
```

### Team Development

```bash
# /etc/port-redirect/config.txt
# Team Development - Shared Port Standards

# Frontend Applications
3000    # Main app
3001    # Admin panel
3002    # Mobile app (web view)

# Backend Services
8000    # User API
8001    # Product API
8002    # Order API

# Development Tools
9000    # Documentation site
9001    # API documentation
9002    # Design system
```

## Status Page Guide

### Accessing the Status Page

Visit `http://localhost/status` or `http://127.0.0.1/status` to view the service status.

### Status Page Sections

#### 1. Service Information
- **Uptime**: How long the service has been running
- **Configuration Loaded**: When the config was last reloaded
- **Version**: Service version information

#### 2. Configuration Status
- **Config File Path**: Location of configuration file
- **Configured Ports**: List of active ports
- **Invalid Entries**: Ports that failed validation

#### 3. Hosts File Status
- **Backup Status**: Whether `/etc/hosts` backup exists
- **Entries Valid**: If all required entries are present
- **Missing Entries**: Domains that should be in hosts file
- **Extra Entries**: Unexpected entries in hosts file

#### 4. Recent Activity
- **Last Redirects**: Recent redirect operations
- **Errors**: Recent error messages
- **Configuration Changes**: Recent config reloads

### Status API Usage

```bash
# Get status as JSON
curl http://localhost/status?format=json

# Check specific status fields
curl -s http://localhost/status?format=json | jq '.uptime'
curl -s http://localhost/status?format=json | jq '.configured_ports'

# Monitor service health
while true; do
  curl -s http://localhost/status?format=json | jq '.last_error // "OK"'
  sleep 5
done
```

### Status Monitoring Script

```bash
#!/bin/bash
# monitor-service.sh

check_service_health() {
    local status_url="http://localhost/status?format=json"
    local response
    
    response=$(curl -s "$status_url" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo "❌ Service is not responding"
        return 1
    fi
    
    local last_error
    last_error=$(echo "$response" | jq -r '.last_error // empty')
    
    if [[ -n "$last_error" ]]; then
        echo "⚠️  Service has errors: $last_error"
        return 1
    fi
    
    echo "✅ Service is healthy"
    return 0
}

# Run health check
check_service_health
```

## Security Considerations

### Permission Requirements

The service requires root privileges for specific operations:

```bash
# Required for port 80 binding
sudo netstat -tlnp | grep :80

# Required for /etc/hosts modification
ls -la /etc/hosts

# Service runs as root
ps aux | grep port-redirect-service
```

### Security Best Practices

#### 1. Limit Configuration Access

```bash
# Secure configuration file permissions
sudo chmod 644 /etc/port-redirect/config.txt
sudo chown root:root /etc/port-redirect/config.txt

# Verify permissions
ls -la /etc/port-redirect/
```

#### 2. Monitor Hosts File Changes

```bash
# Create monitoring script
cat > /usr/local/bin/monitor-hosts.sh << 'EOF'
#!/bin/bash
# Monitor /etc/hosts for unauthorized changes

HOSTS_FILE="/etc/hosts"
BACKUP_FILE="/etc/port-redirect/hosts.backup"

if [[ -f "$BACKUP_FILE" ]]; then
    # Check for unexpected changes
    if ! grep -q "PORT-REDIRECT-SERVICE" "$HOSTS_FILE"; then
        echo "WARNING: Port redirect entries missing from /etc/hosts"
        logger "Port redirect service: hosts file entries missing"
    fi
fi
EOF

sudo chmod +x /usr/local/bin/monitor-hosts.sh
```

#### 3. Audit Configuration Changes

```bash
# Enable file monitoring (Linux with auditd)
sudo auditctl -w /etc/port-redirect/config.txt -p wa -k port-redirect-config

# View audit logs
sudo ausearch -k port-redirect-config
```

#### 4. Network Security

```bash
# Verify service only binds to localhost
sudo netstat -tlnp | grep port-redirect-service

# Should show: 127.0.0.1:80 or 0.0.0.0:80 (local only)
```

### Firewall Configuration

#### macOS (pfctl)

```bash
# Allow localhost traffic (usually default)
# No additional configuration needed for localhost-only service
```

#### Linux (iptables/ufw)

```bash
# Allow localhost traffic
sudo ufw allow from 127.0.0.1 to any port 80

# Or with iptables
sudo iptables -A INPUT -s 127.0.0.1 -p tcp --dport 80 -j ACCEPT
```

## Advanced Configuration

### Dynamic Port Management

```bash
#!/bin/bash
# add-port.sh - Dynamically add ports to configuration

add_port() {
    local port="$1"
    local config_file="/etc/port-redirect/config.txt"
    
    # Validate port number
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        echo "Error: Invalid port number: $port"
        return 1
    fi
    
    # Check if port already exists
    if grep -q "^$port$" "$config_file" 2>/dev/null; then
        echo "Port $port already configured"
        return 0
    fi
    
    # Add port to configuration
    echo "$port" | sudo tee -a "$config_file" > /dev/null
    echo "Added port $port to configuration"
    
    # Verify service reloaded configuration
    sleep 2
    if curl -s "http://localhost/status?format=json" | jq -r '.configured_ports[]' | grep -q "$port"; then
        echo "Port $port is now active"
    else
        echo "Warning: Port $port may not be active yet"
    fi
}

# Usage: ./add-port.sh 3000
add_port "$1"
```

### Configuration Templates

#### Development Team Template

```bash
# /etc/port-redirect/templates/team-dev.txt
# Standard development ports for the team

# Frontend
3000    # Main application
3001    # Admin interface
3002    # Mobile web app

# Backend
8000    # Main API
8001    # Auth service
8002    # File service

# Tools
9000    # Documentation
9001    # Monitoring
```

#### Project-Specific Template

```bash
# /etc/port-redirect/templates/project-alpha.txt
# Project Alpha development ports

5000    # Flask backend
3000    # React frontend
6379    # Redis admin (if using web interface)
5432    # PostgreSQL admin (if using web interface)
```

### Automated Configuration Management

```bash
#!/bin/bash
# manage-config.sh - Configuration management script

TEMPLATES_DIR="/etc/port-redirect/templates"
CONFIG_FILE="/etc/port-redirect/config.txt"

load_template() {
    local template="$1"
    local template_file="$TEMPLATES_DIR/$template.txt"
    
    if [[ ! -f "$template_file" ]]; then
        echo "Template not found: $template"
        return 1
    fi
    
    # Backup current config
    sudo cp "$CONFIG_FILE" "$CONFIG_FILE.backup.$(date +%Y%m%d-%H%M%S)"
    
    # Load template
    sudo cp "$template_file" "$CONFIG_FILE"
    echo "Loaded template: $template"
    
    # Show status
    sleep 2
    sudo ./install.sh status
}

list_templates() {
    echo "Available templates:"
    ls -1 "$TEMPLATES_DIR"/*.txt 2>/dev/null | sed 's|.*/||; s|\.txt$||'
}

case "$1" in
    load)
        load_template "$2"
        ;;
    list)
        list_templates
        ;;
    *)
        echo "Usage: $0 {load|list} [template-name]"
        echo "Examples:"
        echo "  $0 list"
        echo "  $0 load team-dev"
        ;;
esac
```

### Integration with Development Tools

#### VS Code Integration

Create a VS Code task to manage the service:

```json
// .vscode/tasks.json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Port Redirect: Status",
            "type": "shell",
            "command": "sudo ./install.sh status",
            "group": "build",
            "presentation": {
                "echo": true,
                "reveal": "always",
                "focus": false,
                "panel": "shared"
            }
        },
        {
            "label": "Port Redirect: Add Current Port",
            "type": "shell",
            "command": "echo '${input:port}' | sudo tee -a /etc/port-redirect/config.txt",
            "group": "build"
        }
    ],
    "inputs": [
        {
            "id": "port",
            "description": "Port number to add",
            "default": "3000",
            "type": "promptString"
        }
    ]
}
```

#### Package.json Scripts

```json
{
  "scripts": {
    "dev": "npm start",
    "dev:setup": "echo '3000' | sudo tee -a /etc/port-redirect/config.txt && npm start",
    "dev:status": "curl -s http://localhost/status?format=json | jq '.configured_ports'"
  }
}
```

### Troubleshooting Advanced Issues

#### Configuration Reload Issues

```bash
# Force configuration reload
sudo pkill -HUP port-redirect-service

# Or restart service
sudo ./install.sh restart

# Check if file watcher is working
sudo lsof | grep port-redirect | grep config.txt
```

#### Hosts File Corruption Recovery

```bash
# Check for backup
ls -la /etc/port-redirect/hosts.backup

# Restore from backup
sudo cp /etc/port-redirect/hosts.backup /etc/hosts

# Restart service to regenerate entries
sudo ./install.sh restart
```

#### Performance Monitoring

```bash
# Monitor service resource usage
top -p $(pgrep port-redirect-service)

# Check memory usage
ps -o pid,vsz,rss,comm -p $(pgrep port-redirect-service)

# Monitor network connections
sudo netstat -tlnp | grep port-redirect-service
```

## Uninstallation Guide

### Complete Removal

```bash
# Stop and remove service
sudo ./install.sh uninstall

# Verify removal
sudo ./install.sh status  # Should show "not installed"

# Check for leftover files
ls -la /usr/local/bin/port-redirect-service  # Should not exist
ls -la /etc/port-redirect/                   # Should not exist

# Verify hosts file restoration
grep "PORT-REDIRECT-SERVICE" /etc/hosts      # Should be empty
```

### Selective Removal

```bash
# Remove only configuration (keep service)
sudo rm -rf /etc/port-redirect/

# Remove only service files (keep config)
sudo rm /usr/local/bin/port-redirect-service
# Platform-specific service file removal...

# Remove only hosts entries (manual)
sudo sed -i '/BEGIN PORT-REDIRECT-SERVICE/,/END PORT-REDIRECT-SERVICE/d' /etc/hosts
```

### Backup Before Removal

```bash
# Create backup of current setup
mkdir -p ~/port-redirect-backup
sudo cp -r /etc/port-redirect/ ~/port-redirect-backup/
sudo cp /etc/hosts ~/port-redirect-backup/hosts.current

# Then proceed with uninstallation
sudo ./install.sh uninstall
```

---

This usage guide provides comprehensive examples and configuration scenarios to help users get the most out of the Port Redirect Service. For additional support, refer to the main README.md file or check the service logs for troubleshooting.