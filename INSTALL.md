# Installation Guide

## Quick Install

### Prerequisites
1. Build the binary:
   ```bash
   go build -o port-redirect-service
   ```

2. Install the service:
   ```bash
   sudo ./install.sh install
   ```

That's it! The installer automatically detects your platform (macOS or Linux) and installs the appropriate service.

## Platform Support

- ✅ **macOS** - Uses launchd for service management
- ✅ **Linux** - Uses systemd for service management

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

The service reads its configuration from `/etc/port-redirect/config.txt`:

```
# Port Redirect Service Configuration
# One port per line, comments start with #

3000
8080
5173
9000
```

## Verification

1. Check the service status:
   ```bash
   sudo ./install.sh status
   ```

2. Visit the status page:
   ```
   http://localhost/status
   ```

3. Test a redirect (if port 3000 is configured):
   ```bash
   curl -I http://3000.local
   ```

## Troubleshooting

### macOS
- View logs: `tail -f /var/log/port-redirect-service.log`
- Service management: `sudo launchctl list | grep portredirect`

### Linux
- View logs: `journalctl -u port-redirect -f`
- Service management: `systemctl status port-redirect`

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