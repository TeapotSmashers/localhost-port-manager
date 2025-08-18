# Port Redirect Service

A lightweight Go service that runs as a system daemon to automatically redirect domain requests with port numbers to localhost. When you type `3000.ai` in your browser, the service intercepts the request and redirects it to `localhost:3000`, eliminating the need to manually type localhost URLs during development.

## Features

- 🚀 **Zero Configuration**: Works out of the box with sensible defaults
- 🔄 **Dynamic Configuration**: Hot-reload configuration without service restart
- 🖥️ **Cross-Platform**: Supports both macOS (launchd) and Linux (systemd)
- 📊 **Web Status Interface**: Monitor service status at `http://localhost/status`
- 🛡️ **Safe Hosts Management**: Automatic backup and restore of `/etc/hosts`
- 📝 **Comprehensive Logging**: Detailed logs for troubleshooting
- ⚡ **Lightweight**: Single binary with no external dependencies

## Quick Start

### Prerequisites

1. **Go 1.19+** (for building from source)
2. **Root/Administrator privileges** (required for port 80 and `/etc/hosts` modification)

### Installation

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

That's it! The installer automatically detects your platform and configures the appropriate system service.

## Platform Support

| Platform | Service Manager | Status |
|----------|----------------|--------|
| macOS    | launchd        | ✅ Supported |
| Linux    | systemd        | ✅ Supported |
| Windows  | -              | ❌ Not supported |

## How It Works

1. **Domain Resolution**: The service adds entries to `/etc/hosts` that point configured domains to localhost
2. **HTTP Interception**: Service listens on port 80 and intercepts requests
3. **Port Extraction**: Extracts port number from domain format `<port>.<tld>`
4. **Redirect**: Issues HTTP 301 redirect to `localhost:<port>`

```
Browser Request (3000.ai) 
    ↓
/etc/hosts (points to localhost:80)
    ↓
Port Redirect Service (localhost:80)
    ↓
HTTP 301 Redirect (localhost:3000)
    ↓
Your Local Server (localhost:3000)
```

## Configuration

### Configuration File

The service reads configuration from `/etc/port-redirect/config.txt`:

```bash
# Port Redirect Service Configuration
# One port per line, comments start with #

3000    # React development server
8080    # Common HTTP alternative
5173    # Vite development server
9000    # Custom application
4000    # Another common port
```

### Supported Domain Formats

The service supports these TLD patterns:
- `<port>.local` (e.g., `3000.local`)
- `<port>.dev` (e.g., `8080.dev`)
- `<port>.test` (e.g., `5173.test`)
- `<port>.localhost` (e.g., `9000.localhost`)

### Configuration Management

- **Hot Reload**: Configuration changes are detected automatically
- **Validation**: Invalid port numbers (outside 1-65535) are ignored
- **Comments**: Lines starting with `#` are treated as comments
- **Default Ports**: If no config file exists, defaults to ports 3000, 8080, 5173

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

Visit `http://localhost/status` to view:

- **Service Status**: Uptime, configuration load time
- **Configuration**: Current port list and file path
- **Hosts File Status**: Validation of `/etc/hosts` entries
- **Error Information**: Recent errors and troubleshooting hints

### Status API

The status endpoint also provides JSON data:

```bash
curl http://localhost/status?format=json
```

## Troubleshooting

### Common Issues

#### 1. Service Won't Start

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

#### 2. Redirects Not Working

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

#### 3. Configuration Not Loading

**Symptoms:**
- Changes to config file not taking effect
- Status page shows old configuration

**Solutions:**
```bash
# Check config file syntax
cat /etc/port-redirect/config.txt

# Restart service to force reload
sudo ./install.sh restart

# Verify file permissions
ls -la /etc/port-redirect/config.txt
```

#### 4. Permission Errors

**Symptoms:**
- "Operation not permitted" errors
- Service can't modify `/etc/hosts`

**Solutions:**
```bash
# Ensure running with sudo
sudo ./install.sh status

# Check hosts file permissions
ls -la /etc/hosts

# Verify service is running as root
# macOS:
sudo launchctl list | grep portredirect

# Linux:
systemctl status port-redirect
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