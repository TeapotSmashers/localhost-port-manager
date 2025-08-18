# Installation Guide

This guide covers installation for both Local Mode and Web Service Mode deployments.

## Quick Install (Local Mode)

### Prerequisites
1. **Go 1.19+** (for building from source)
2. **Root privileges** (required for port 80 and `/etc/hosts` modification)

### Installation Steps
1. Build the binary:
   ```bash
   go build -o port-redirect-service
   ```

2. Install the service:
   ```bash
   sudo ./install.sh install
   ```

That's it! The installer automatically detects your platform (macOS or Linux) and installs the appropriate service in Local Mode.

## Web Service Mode Installation

### Prerequisites
1. **Go 1.19+** (for building from source)
2. **Server with public IP** (for external access)
3. **Domain name with DNS control**
4. **Standard user privileges** (root not required for web service mode)

### Installation Steps

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

3. **Install the service:**
   ```bash
   sudo ./install.sh install
   ```

4. **Configure firewall:**
   ```bash
   # Ubuntu/Debian
   sudo ufw allow 8080/tcp
   
   # CentOS/RHEL
   sudo firewall-cmd --permanent --add-port=8080/tcp
   sudo firewall-cmd --reload
   ```

5. **Set up DNS (external step):**
   Configure DNS records to point `*.yourdomain.com` to your server IP.

## Platform Support

- ✅ **macOS** - Uses launchd for service management
- ✅ **Linux** - Uses systemd for service management
- ✅ **Both modes** - Local Mode and Web Service Mode supported on both platforms

## Service Management

After installation, use these commands to manage the service:

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
```

## Configuration

### Local Mode Configuration (Default)

The service reads its configuration from `/etc/port-redirect/config.txt`:

```bash
# Port Redirect Service Configuration
# One port per line, comments start with #

3000    # React development server
8080    # Backend API
5173    # Vite dev server
9000    # Custom application

# Local mode is default (no additional config needed)
```

### Web Service Mode Configuration

For web service deployment, add mode-specific settings:

```bash
# Port configuration (same as local mode)
3000
8080
5173
9000

# Web service mode settings
mode=web
web_port=8080
domain_patterns=*.yourdomain.com,*.dev.yourdomain.com

# Optional security settings
enable_rate_limit=true
rate_limit_rps=100
```

### Configuration Parameters

#### Common Parameters
- **Port numbers**: One per line, range 1-65535
- **Comments**: Lines starting with `#`

#### Web Service Mode Parameters
- **mode=web**: Enable web service mode
- **web_port=PORT**: Service listening port (default: 8080)
- **domain_patterns=PATTERNS**: Comma-separated domain patterns (required for web mode)
- **enable_rate_limit=BOOL**: Enable rate limiting (default: false)
- **rate_limit_rps=NUMBER**: Requests per second limit (default: 100)

## Verification

### Local Mode Verification

1. Check the service status:
   ```bash
   sudo ./install.sh status
   ```

2. Visit the status page:
   ```bash
   curl http://localhost/status
   ```

3. Test a redirect (if port 3000 is configured):
   ```bash
   curl -I http://3000.local
   ```

4. Verify hosts file entries:
   ```bash
   cat /etc/hosts | grep "PORT-REDIRECT-SERVICE"
   ```

### Web Service Mode Verification

1. Check the service status:
   ```bash
   sudo ./install.sh status
   ```

2. Verify service is listening on web port:
   ```bash
   sudo netstat -tlnp | grep :8080
   ```

3. Test local access with Host header:
   ```bash
   curl -I -H "Host: 3000.yourdomain.com" http://localhost:8080
   ```

4. Visit the web service status page:
   ```bash
   curl http://your-server:8080/status
   ```

5. Test external access (after DNS setup):
   ```bash
   curl -I http://3000.yourdomain.com
   ```

6. Check web service metrics:
   ```bash
   curl http://your-server:8080/status?format=json | jq '.web_service_metrics'
   ```

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check configuration syntax
cat /etc/port-redirect/config.txt

# Check for port conflicts
sudo lsof -i :80    # Local mode
sudo lsof -i :8080  # Web service mode (or your configured port)

# Check service logs
# macOS:
tail -f /var/log/port-redirect-service.log

# Linux:
journalctl -u port-redirect -f
```

#### Configuration Issues
```bash
# Validate configuration format
grep -E "^[0-9]+$|^[a-z_]+=|^#|^$" /etc/port-redirect/config.txt

# Check for invalid port numbers
awk '/^[0-9]+$/ { if ($1 < 1 || $1 > 65535) print "Invalid port: " $1 }' /etc/port-redirect/config.txt

# Test configuration without starting service
./port-redirect-service -config /etc/port-redirect/config.txt -test
```

#### Web Service Mode Issues
```bash
# Check domain pattern configuration
grep "domain_patterns=" /etc/port-redirect/config.txt

# Test domain pattern matching
curl -I -H "Host: 3000.yourdomain.com" http://localhost:8080

# Check firewall settings
sudo ufw status  # Ubuntu/Debian
sudo firewall-cmd --list-all  # CentOS/RHEL
```

### Platform-Specific Troubleshooting

#### macOS
- View logs: `tail -f /var/log/port-redirect-service.log`
- Service management: `sudo launchctl list | grep portredirect`
- Check service file: `cat /Library/LaunchDaemons/com.portredirect.service.plist`

#### Linux
- View logs: `journalctl -u port-redirect -f`
- Service management: `systemctl status port-redirect`
- Check service file: `cat /etc/systemd/system/port-redirect.service`

## Manual Installation

If you prefer platform-specific installation:

### macOS
```bash
cd scripts/macos
sudo ./install.sh install
```

### Linux
```bash
cd scripts/linux
sudo ./install.sh install
```

## Uninstallation

To completely remove the service:

```bash
sudo ./install.sh uninstall
```

This will:
- Stop and disable the service
- Remove the binary and service files
- Optionally remove the configuration directory
- Restore the original `/etc/hosts` file