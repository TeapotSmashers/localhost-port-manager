# Port Redirect Service

A lightweight Go service that operates in two deployment modes: **Local Mode** for development workstations and **Web Service Mode** for deployed environments. In Local Mode, it modifies `/etc/hosts` to redirect domains like `3000.local` to `localhost:3000`. In Web Service Mode, it acts as a deployed service that redirects subdomain requests like `3000.sankalpmukim.dev` to localhost ports.

## Features

- 🚀 **Dual Deployment Modes**: Local development and web service deployment
- 🔄 **Dynamic Configuration**: Hot-reload configuration without service restart
- 🖥️ **Cross-Platform**: Supports both macOS (launchd) and Linux (systemd)
- 📊 **Web Status Interface**: Monitor service status and metrics
- 🛡️ **Safe Hosts Management**: Automatic backup and restore of `/etc/hosts` (Local Mode)
- 🌐 **Domain Pattern Matching**: Flexible subdomain patterns (Web Service Mode)
- 🚦 **Rate Limiting**: Optional per-IP rate limiting (Web Service Mode)
- 📝 **Comprehensive Logging**: Detailed logs for troubleshooting
- ⚡ **Lightweight**: Single binary with no external dependencies

## Deployment Modes

### Local Mode (Default)
- Modifies `/etc/hosts` to redirect domains like `3000.local` to localhost
- Requires root privileges for port 80 and hosts file modification
- Perfect for local development workstations

### Web Service Mode
- Deployed service that handles subdomain redirects like `3000.yourdomain.com`
- No hosts file modification required
- Configurable port binding and domain patterns
- Optional rate limiting and enhanced security

## Quick Start

### Local Mode Installation

1. **Build the binary:**
   ```bash
   go build -o port-redirect-service
   ```

2. **Install the service:**
   ```bash
   sudo ./install.sh install
   ```

3. **Verify installation:**
   ```bash
   sudo ./install.sh status
   ```

4. **Test the service:**
   ```bash
   # Visit in browser or use curl
   curl -I http://3000.local
   # Should redirect to localhost:3000
   ```

### Web Service Mode Setup

1. **Build the binary:**
   ```bash
   go build -o port-redirect-service
   ```

2. **Create web service configuration:**
   ```bash
   sudo mkdir -p /etc/port-redirect
   sudo tee /etc/port-redirect/config.txt << EOF
   # Port configuration
   3000
   8080
   5173
   
   # Web service mode
   mode=web
   web_port=8080
   domain_patterns=*.yourdomain.com
   
   # Optional rate limiting
   enable_rate_limit=true
   rate_limit_rps=100
   EOF
   ```

3. **Install and start the service:**
   ```bash
   sudo ./install.sh install
   sudo ./install.sh start
   ```

4. **Test the web service:**
   ```bash
   # Assuming DNS points *.yourdomain.com to your server
   curl -I http://3000.yourdomain.com
   # Should redirect to localhost:3000
   ```

## Platform Support

| Platform | Service Manager | Status |
|----------|----------------|--------|
| macOS    | launchd        | ✅ Supported |
| Linux    | systemd        | ✅ Supported |
| Windows  | -              | ❌ Not supported |

## How It Works

### Local Mode Flow
1. **Domain Resolution**: The service adds entries to `/etc/hosts` that point configured domains to localhost
2. **HTTP Interception**: Service listens on port 80 and intercepts requests
3. **Port Extraction**: Extracts port number from domain format `<port>.<tld>`
4. **Redirect**: Issues HTTP 301 redirect to `localhost:<port>`

```
Browser Request (3000.local) 
    ↓
/etc/hosts (points to localhost:80)
    ↓
Port Redirect Service (localhost:80)
    ↓
HTTP 301 Redirect (localhost:3000)
    ↓
Your Local Server (localhost:3000)
```

### Web Service Mode Flow
1. **DNS Resolution**: External DNS points `*.yourdomain.com` to your server
2. **HTTP Interception**: Service listens on configured port (e.g., 8080)
3. **Domain Pattern Matching**: Validates request against configured domain patterns
4. **Port Extraction**: Extracts port number from subdomain format `<port>.yourdomain.com`
5. **Rate Limiting**: Optional per-IP rate limiting (if enabled)
6. **Redirect**: Issues HTTP 301 redirect to `localhost:<port>`

```
Browser Request (3000.yourdomain.com)
    ↓
DNS Resolution (points to your server IP)
    ↓
Port Redirect Service (your-server:8080)
    ↓
Domain Pattern Validation
    ↓
Rate Limiting Check (optional)
    ↓
HTTP 301 Redirect (localhost:3000)
    ↓
Your Local Server (localhost:3000)
```

## Configuration

### Configuration File Format

The service reads configuration from `/etc/port-redirect/config.txt`. The format supports both deployment modes:

#### Local Mode Configuration (Default)
```bash
# Port Redirect Service Configuration
# One port per line, comments start with #

3000    # React development server
8080    # Common HTTP alternative
5173    # Vite development server
9000    # Custom application

# Mode is automatically detected as 'local' if not specified
```

#### Web Service Mode Configuration
```bash
# Port configuration (same for both modes)
3000
8080
5173
9000

# Deployment mode
mode=web

# Web service specific settings
web_port=8080
domain_patterns=*.sankalpmukim.dev,*.example.com

# Optional rate limiting
enable_rate_limit=true
rate_limit_rps=100
```

### Configuration Parameters

#### Common Parameters
- **Port numbers**: One per line, valid range 1-65535
- **Comments**: Lines starting with `#` are ignored
- **Empty lines**: Ignored for readability

#### Local Mode Parameters
- **mode=local**: Explicitly set local mode (optional, this is the default)

#### Web Service Mode Parameters
- **mode=web**: Enable web service mode
- **web_port=PORT**: Port for the web service to listen on (default: 8080)
- **domain_patterns=PATTERNS**: Comma-separated list of domain patterns (required)
- **enable_rate_limit=BOOL**: Enable per-IP rate limiting (default: false)
- **rate_limit_rps=NUMBER**: Requests per second limit (default: 100)

### Domain Pattern Examples

#### Web Service Mode Domain Patterns
- `*.sankalpmukim.dev` - Matches `3000.sankalpmukim.dev`, `8080.sankalpmukim.dev`
- `*.example.com` - Matches `3000.example.com`, `5173.example.com`
- `*.dev.local` - Matches `3000.dev.local`, `8080.dev.local`

#### Local Mode Domain Formats (Automatic)
- `<port>.local` (e.g., `3000.local`)
- `<port>.dev` (e.g., `8080.dev`)
- `<port>.test` (e.g., `5173.test`)
- `<port>.localhost` (e.g., `9000.localhost`)

### Configuration Management

- **Hot Reload**: Configuration changes are detected automatically
- **Validation**: Invalid port numbers and configurations are logged and ignored
- **Mode Detection**: Automatically detects deployment mode from configuration
- **Backward Compatibility**: Existing local mode configurations continue to work

## Deployment Mode Configuration

### Switching Between Modes

You can switch between deployment modes by modifying the configuration file:

#### Switch to Web Service Mode
```bash
# Edit configuration
sudo tee -a /etc/port-redirect/config.txt << EOF

# Enable web service mode
mode=web
web_port=8080
domain_patterns=*.yourdomain.com
EOF

# Restart service to apply changes
sudo ./install.sh restart
```

#### Switch to Local Mode
```bash
# Edit configuration to remove or comment out web service settings
sudo sed -i 's/^mode=web/#mode=web/' /etc/port-redirect/config.txt
sudo sed -i 's/^web_port=/#web_port=/' /etc/port-redirect/config.txt
sudo sed -i 's/^domain_patterns=/#domain_patterns=/' /etc/port-redirect/config.txt

# Restart service to apply changes
sudo ./install.sh restart
```

### Complete Configuration Examples

#### Local Development Setup
```bash
# /etc/port-redirect/config.txt
# Local development configuration

# Development ports
3000    # React/Next.js
8080    # Backend API
5173    # Vite dev server
4200    # Angular CLI

# Local mode (default - no additional config needed)
# Service will listen on port 80 and modify /etc/hosts
```

#### Web Service Deployment
```bash
# /etc/port-redirect/config.txt
# Web service deployment configuration

# Application ports
3000    # Frontend application
8000    # Main API
8001    # Auth service
8002    # File service

# Web service mode
mode=web
web_port=8080
domain_patterns=*.sankalpmukim.dev,*.example.com

# Security and performance
enable_rate_limit=true
rate_limit_rps=100
```

#### Multi-Environment Setup
```bash
# /etc/port-redirect/config.txt
# Multi-environment configuration

# Development ports
3000    # Dev frontend
8000    # Dev API

# Staging ports  
3100    # Staging frontend
8100    # Staging API

# Production ports
3200    # Prod frontend
8200    # Prod API

# Web service mode for remote access
mode=web
web_port=80
domain_patterns=*.dev.company.com,*.staging.company.com,*.prod.company.com

# Enhanced security for production
enable_rate_limit=true
rate_limit_rps=50
```

## Service Management

### Universal Commands (Recommended)

```bash
# Check service status
sudo ./install.sh status

# Start the service
sudo ./install.sh start

# Stop the service
sudo ./install.sh stop

# Restart the service
sudo ./install.sh restart

# Uninstall the service
sudo ./install.sh uninstall

# Validate installation files
./install.sh validate
```

### Platform-Specific Commands

#### macOS (launchd)

```bash
# Service status
sudo launchctl list | grep portredirect

# Manual service control
sudo launchctl load /Library/LaunchDaemons/com.portredirect.service.plist
sudo launchctl unload /Library/LaunchDaemons/com.portredirect.service.plist

# View logs
tail -f /var/log/port-redirect-service.log
```

#### Linux (systemd)

```bash
# Service status
systemctl status port-redirect

# Manual service control
sudo systemctl start port-redirect
sudo systemctl stop port-redirect
sudo systemctl restart port-redirect

# Enable/disable auto-start
sudo systemctl enable port-redirect
sudo systemctl disable port-redirect

# View logs
journalctl -u port-redirect -f
```

## Status Interface

### Local Mode Status
Visit `http://localhost/status` to view:
- **Service Status**: Uptime, configuration load time
- **Configuration**: Current port list and file path
- **Hosts File Status**: Validation of `/etc/hosts` entries
- **Error Information**: Recent errors and troubleshooting hints

### Web Service Mode Status
Visit `http://your-server:web_port/status` to view:
- **Service Status**: Uptime, deployment mode, configuration
- **Web Service Metrics**: Request counts, successful redirects, failed requests
- **Domain Patterns**: Configured domain patterns and validation
- **Rate Limiting**: Rate limit statistics (if enabled)
- **Security Information**: Request validation and error logs

### Status API

#### Local Mode
```bash
curl http://localhost/status?format=json
```

#### Web Service Mode
```bash
curl http://your-server:8080/status?format=json

# Example response for web service mode
{
  "uptime": "2h30m15s",
  "deployment_mode": "web",
  "ports_configured": [3000, 8080, 5173],
  "web_service_metrics": {
    "domain_patterns": ["*.sankalpmukim.dev"],
    "request_count": 1250,
    "successful_redirects": 1180,
    "failed_requests": 70,
    "rate_limited_requests": 15,
    "unique_ips": 45,
    "port_usage_stats": {
      "3000": 800,
      "8080": 380,
      "5173": 70
    }
  }
}
```

### Health Check Endpoint

Web Service Mode includes a dedicated health check endpoint for load balancers:

```bash
curl http://your-server:8080/health

# Response: 200 OK with JSON health status
{
  "status": "healthy",
  "deployment_mode": "web",
  "domain_patterns_count": 2,
  "request_count": 1250
}
```

## Troubleshooting

### Common Issues by Deployment Mode

#### Local Mode Issues

##### 1. Service Won't Start (Local Mode)
**Symptoms:**
- Service fails to start after installation
- "Permission denied" errors

**Solutions:**
```bash
# Check if port 80 is already in use
sudo lsof -i :80

# Verify service has proper permissions
sudo ./install.sh status

# Check logs for detailed error messages
# macOS:
tail -f /var/log/port-redirect-service.log

# Linux:
journalctl -u port-redirect -f
```

##### 2. Redirects Not Working (Local Mode)
**Symptoms:**
- Domains resolve but don't redirect
- Browser shows "connection refused"

**Solutions:**
```bash
# Verify hosts file entries
cat /etc/hosts | grep "PORT-REDIRECT-SERVICE"

# Check service status
sudo ./install.sh status

# Test redirect manually
curl -I http://3000.local

# Verify target service is running
curl http://localhost:3000
```

##### 3. Hosts File Issues (Local Mode)
**Symptoms:**
- Hosts file entries missing or corrupted
- Service can't modify `/etc/hosts`

**Solutions:**
```bash
# Check hosts file permissions
ls -la /etc/hosts

# Restore from backup if available
sudo cp /etc/port-redirect/hosts.backup /etc/hosts

# Restart service to regenerate entries
sudo ./install.sh restart
```

#### Web Service Mode Issues

##### 1. Service Won't Start (Web Service Mode)
**Symptoms:**
- Service fails to start in web mode
- Port binding errors

**Solutions:**
```bash
# Check if configured web port is in use
sudo lsof -i :8080  # Replace with your web_port

# Verify web service configuration
cat /etc/port-redirect/config.txt | grep -E "mode=|web_port=|domain_patterns="

# Check for configuration errors
sudo ./install.sh status

# Test port binding manually
telnet localhost 8080  # Replace with your web_port
```

##### 2. Domain Pattern Not Matching (Web Service Mode)
**Symptoms:**
- Requests return 404 Not Found
- Domain patterns not working

**Solutions:**
```bash
# Test domain pattern matching
curl -I -H "Host: 3000.yourdomain.com" http://your-server:8080

# Check configured patterns
curl http://your-server:8080/status?format=json | jq '.web_service_metrics.domain_patterns'

# Verify DNS resolution
nslookup 3000.yourdomain.com

# Test with different patterns
curl -I -H "Host: 8080.yourdomain.com" http://your-server:8080
```

##### 3. Rate Limiting Issues (Web Service Mode)
**Symptoms:**
- Requests return 429 Too Many Requests
- Legitimate requests being blocked

**Solutions:**
```bash
# Check rate limit configuration
cat /etc/port-redirect/config.txt | grep rate_limit

# View rate limit statistics
curl http://your-server:8080/status?format=json | jq '.web_service_metrics.rate_limited_requests'

# Temporarily disable rate limiting
sudo sed -i 's/enable_rate_limit=true/enable_rate_limit=false/' /etc/port-redirect/config.txt
sudo ./install.sh restart

# Adjust rate limit settings
sudo sed -i 's/rate_limit_rps=50/rate_limit_rps=200/' /etc/port-redirect/config.txt
sudo ./install.sh restart
```

##### 4. DNS and Network Issues (Web Service Mode)
**Symptoms:**
- Subdomains not resolving to server
- External access not working

**Solutions:**
```bash
# Verify DNS configuration
dig 3000.yourdomain.com
nslookup 3000.yourdomain.com

# Check firewall settings
sudo ufw status  # Linux
sudo pfctl -sr   # macOS

# Test local access first
curl -I -H "Host: 3000.yourdomain.com" http://localhost:8080

# Check server binding
sudo netstat -tlnp | grep :8080
```

#### Universal Issues

##### 1. Configuration Not Loading
**Symptoms:**
- Changes to config file not taking effect
- Status page shows old configuration

**Solutions:**
```bash
# Check config file syntax
cat /etc/port-redirect/config.txt

# Validate configuration format
grep -E "^[0-9]+$|^[a-z_]+=|^#|^$" /etc/port-redirect/config.txt

# Restart service to force reload
sudo ./install.sh restart

# Verify file permissions
ls -la /etc/port-redirect/config.txt

# Check for file watcher issues
sudo lsof | grep port-redirect | grep config.txt
```

##### 2. Permission Errors
**Symptoms:**
- "Operation not permitted" errors
- Service startup failures

**Solutions:**
```bash
# Ensure running with sudo
sudo ./install.sh status

# Check service user
# macOS:
sudo launchctl list | grep portredirect

# Linux:
systemctl status port-redirect

# Verify file permissions
ls -la /etc/port-redirect/
ls -la /usr/local/bin/port-redirect-service
```

### Log Locations

| Platform | Log File Location |
|----------|-------------------|
| macOS    | `/var/log/port-redirect-service.log` |
| Linux    | `journalctl -u port-redirect` |

### Debug Mode

Enable verbose logging by modifying the service configuration:

#### macOS
Edit `/Library/LaunchDaemons/com.portredirect.service.plist` and add:
```xml
<key>EnvironmentVariables</key>
<dict>
    <key>LOG_LEVEL</key>
    <string>DEBUG</string>
</dict>
```

#### Linux
Edit `/etc/systemd/system/port-redirect.service` and add:
```ini
Environment=LOG_LEVEL=DEBUG
```

Then restart the service:
```bash
sudo ./install.sh restart
```

## Security Considerations

### Required Permissions

The service requires root privileges for:

1. **Port 80 Binding**: Only root can bind to privileged ports (< 1024)
2. **Hosts File Modification**: `/etc/hosts` requires root write access
3. **System Service Installation**: Installing system services requires elevated privileges

### Security Measures

- **Input Validation**: Strict validation of host headers and port numbers
- **Minimal Attack Surface**: No external dependencies, simple HTTP handlers only
- **File Permissions**: Secure handling of configuration and hosts files
- **Backup Strategy**: Automatic backup of `/etc/hosts` before modification
- **Graceful Degradation**: Continues operating even if hosts file modification fails

### Network Security

- **Local Only**: Service only handles localhost redirects
- **No External Access**: Does not proxy or forward external requests
- **Port Validation**: Only accepts valid port numbers (1-65535)
- **Domain Validation**: Only processes configured domain patterns

## Advanced Usage

### Custom Installation Paths

For custom installations, use platform-specific scripts:

#### macOS Custom Install
```bash
cd scripts/macos
sudo ./install.sh install
```

#### Linux Custom Install
```bash
cd scripts/linux
sudo ./install.sh install
```

### Multiple Port Ranges

Configure multiple development environments:

```bash
# Frontend development
3000
3001
3002

# Backend services  
8000
8080
8081

# Database interfaces
5432
3306
27017
```

### Integration with Development Tools

#### React/Vite Projects
```bash
# Add to config.txt
3000    # Create React App
5173    # Vite dev server
```

#### Node.js Projects
```bash
# Add to config.txt
3000    # Express default
8000    # Common Node.js port
```

#### Docker Development
```bash
# Add to config.txt
8080    # Docker exposed ports
9000    # Container services
```

## Uninstallation

To completely remove the service:

```bash
sudo ./install.sh uninstall
```

This will:
- Stop and disable the service
- Remove the binary (`/usr/local/bin/port-redirect-service`)
- Remove service files (launchd plist or systemd service)
- Remove configuration directory (`/etc/port-redirect/`)
- Restore the original `/etc/hosts` file from backup
- Clean up log files

### Manual Cleanup (if needed)

If automatic uninstallation fails:

#### macOS Manual Cleanup
```bash
# Stop and remove service
sudo launchctl unload /Library/LaunchDaemons/com.portredirect.service.plist
sudo rm /Library/LaunchDaemons/com.portredirect.service.plist

# Remove binary and config
sudo rm /usr/local/bin/port-redirect-service
sudo rm -rf /etc/port-redirect/

# Restore hosts file (if backup exists)
sudo cp /etc/port-redirect/hosts.backup /etc/hosts
```

#### Linux Manual Cleanup
```bash
# Stop and disable service
sudo systemctl stop port-redirect
sudo systemctl disable port-redirect
sudo rm /etc/systemd/system/port-redirect.service
sudo systemctl daemon-reload

# Remove binary and config
sudo rm /usr/local/bin/port-redirect-service
sudo rm -rf /etc/port-redirect/

# Restore hosts file (if backup exists)
sudo cp /etc/port-redirect/hosts.backup /etc/hosts
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd port-redirect-service

# Build binary
go build -o port-redirect-service

# Run tests
go test ./...

# Test installation (in VM or container)
sudo ./install.sh install
```

## License

[Add your license information here]

## Support

For issues and questions:
- Check the [Troubleshooting](#troubleshooting) section
- Review logs for error details
- Create an issue in the repository

---

**Note**: This service modifies system files (`/etc/hosts`) and requires root privileges. Always review the code and test in a safe environment before production use.