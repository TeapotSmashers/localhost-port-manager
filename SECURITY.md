# Security Considerations

This document outlines the security implications, requirements, and best practices for the Port Redirect Service.

## Table of Contents

- [Security Overview](#security-overview)
- [Permission Requirements](#permission-requirements)
- [Attack Surface Analysis](#attack-surface-analysis)
- [Security Best Practices](#security-best-practices)
- [Monitoring and Auditing](#monitoring-and-auditing)
- [Incident Response](#incident-response)

## Security Overview

The Port Redirect Service requires elevated privileges to function properly, which introduces security considerations that must be carefully managed.

### Security Model

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Boundaries                      │
├─────────────────────────────────────────────────────────────┤
│ System Level (Root Required)                                │
│ ├─ Port 80 Binding                                         │
│ ├─ /etc/hosts Modification                                 │
│ └─ System Service Installation                             │
├─────────────────────────────────────────────────────────────┤
│ Application Level (Controlled Access)                       │
│ ├─ Configuration File Access                               │
│ ├─ HTTP Request Processing                                 │
│ └─ Status Interface                                        │
├─────────────────────────────────────────────────────────────┤
│ Network Level (Local Only)                                 │
│ ├─ Localhost Binding Only                                  │
│ ├─ No External Network Access                             │
│ └─ Input Validation                                        │
└─────────────────────────────────────────────────────────────┘
```

## Permission Requirements

### Why Root Access is Required

The service requires root privileges for three critical operations:

#### 1. Port 80 Binding
```bash
# Only root can bind to privileged ports (< 1024)
# This is enforced by the operating system kernel

# Verification:
sudo netstat -tlnp | grep :80
# Should show the service bound to port 80
```

**Security Implication**: Any process that can bind to port 80 has significant network privileges.

#### 2. /etc/hosts File Modification
```bash
# System hosts file requires root write access
ls -la /etc/hosts
# -rw-r--r-- 1 root root (Linux)
# -rw-r--r-- 1 root wheel (macOS)
```

**Security Implication**: Modifying `/etc/hosts` can redirect any domain to any IP address system-wide.

#### 3. System Service Installation
```bash
# Installing system services requires elevated privileges
# macOS: /Library/LaunchDaemons/ (root-owned)
# Linux: /etc/systemd/system/ (root-owned)
```

**Security Implication**: System services run with high privileges and start automatically.

### Privilege Escalation Risks

#### Risk Assessment

| Risk Level | Component | Mitigation |
|------------|-----------|------------|
| **HIGH** | Root execution | Minimal code surface, input validation |
| **MEDIUM** | Hosts file modification | Backup/restore, validation |
| **MEDIUM** | Network binding | Localhost only, input sanitization |
| **LOW** | Configuration access | File permissions, validation |

## Attack Surface Analysis

### 1. Network Attack Surface

#### HTTP Request Processing
```go
// Potential attack vectors:
// - Malformed Host headers
// - Injection attacks via headers
// - DoS via request flooding
```

**Mitigations Implemented:**
- Strict regex validation of Host headers
- Input sanitization for all user data
- No external network access
- Minimal HTTP handler surface

#### Status Interface
```bash
# Accessible endpoints:
# GET /status - Read-only status information
# GET /status?format=json - JSON API

# No write operations exposed
# No file upload capabilities
# No user authentication (local access only)
```

### 2. File System Attack Surface

#### Configuration File Access
```bash
# Configuration file: /etc/port-redirect/config.txt
# Permissions: 644 (root:root)
# Content: Port numbers only (validated)
```

**Attack Vectors:**
- Configuration file tampering
- Symlink attacks
- Path traversal

**Mitigations:**
- Strict file permission enforcement
- Input validation (port numbers only)
- Absolute path usage
- File integrity checking

#### Hosts File Modification
```bash
# Target file: /etc/hosts
# Backup created before modification
# Managed section markers used
```

**Attack Vectors:**
- Hosts file corruption
- DNS hijacking via malicious entries
- System-wide domain redirection

**Mitigations:**
- Automatic backup creation
- Managed section boundaries
- Validation of entries
- Restore capability

### 3. Process Attack Surface

#### Service Process
```bash
# Process runs as root
# Minimal dependencies (standard library only)
# No external network connections
# No shell command execution
```

**Attack Vectors:**
- Memory corruption vulnerabilities
- Logic bugs in request processing
- Signal handling vulnerabilities

**Mitigations:**
- Go memory safety
- Minimal code complexity
- Input validation
- Graceful error handling

## Security Best Practices

### 1. Installation Security

#### Pre-Installation Validation
```bash
# Verify binary integrity
sha256sum port-redirect-service

# Check for existing malicious processes
ps aux | grep -i redirect
netstat -tlnp | grep :80

# Validate installation files
./install.sh validate
```

#### Secure Installation Process
```bash
# Use official installation method
sudo ./install.sh install

# Verify installation
sudo ./install.sh status

# Check service permissions
ps aux | grep port-redirect-service
ls -la /usr/local/bin/port-redirect-service
```

### 2. Configuration Security

#### Secure Configuration Management
```bash
# Set proper file permissions
sudo chmod 644 /etc/port-redirect/config.txt
sudo chown root:root /etc/port-redirect/config.txt

# Validate configuration content
sudo cat /etc/port-redirect/config.txt | grep -E '^[0-9]+$|^#|^$'

# Monitor configuration changes
sudo auditctl -w /etc/port-redirect/config.txt -p wa -k port-redirect-config
```

#### Configuration Validation
```bash
#!/bin/bash
# validate-config.sh - Validate configuration security

CONFIG_FILE="/etc/port-redirect/config.txt"

validate_config() {
    # Check file permissions
    local perms=$(stat -c "%a" "$CONFIG_FILE" 2>/dev/null)
    if [[ "$perms" != "644" ]]; then
        echo "WARNING: Configuration file has incorrect permissions: $perms"
        return 1
    fi
    
    # Check ownership
    local owner=$(stat -c "%U:%G" "$CONFIG_FILE" 2>/dev/null)
    if [[ "$owner" != "root:root" ]]; then
        echo "WARNING: Configuration file has incorrect ownership: $owner"
        return 1
    fi
    
    # Validate content
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ ]] || [[ -z "$line" ]] && continue
        
        # Validate port numbers
        if ! [[ "$line" =~ ^[0-9]+$ ]] || [[ "$line" -lt 1 ]] || [[ "$line" -gt 65535 ]]; then
            echo "WARNING: Invalid port number in config: $line"
            return 1
        fi
    done < "$CONFIG_FILE"
    
    echo "Configuration validation passed"
    return 0
}

validate_config
```

### 3. Runtime Security

#### Process Monitoring
```bash
# Monitor service process
watch 'ps aux | grep port-redirect-service'

# Check for unexpected network connections
sudo netstat -tlnp | grep port-redirect-service

# Monitor resource usage
top -p $(pgrep port-redirect-service)
```

#### Log Monitoring
```bash
# Monitor service logs for security events
# macOS:
tail -f /var/log/port-redirect-service.log | grep -i "error\|warning\|security"

# Linux:
journalctl -u port-redirect -f | grep -i "error\|warning\|security"
```

### 4. Network Security

#### Firewall Configuration
```bash
# Ensure service only accepts local connections
# Linux (ufw):
sudo ufw deny 80
sudo ufw allow from 127.0.0.1 to any port 80

# Linux (iptables):
sudo iptables -A INPUT -p tcp --dport 80 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j DROP
```

#### Network Monitoring
```bash
# Monitor network connections
sudo ss -tlnp | grep port-redirect-service

# Check for unexpected external connections
sudo netstat -an | grep :80 | grep -v 127.0.0.1
```

## Monitoring and Auditing

### 1. Security Event Logging

#### Enable Audit Logging (Linux)
```bash
# Install auditd if not present
sudo apt-get install auditd  # Debian/Ubuntu
sudo yum install audit       # RHEL/CentOS

# Add audit rules
sudo auditctl -w /etc/port-redirect/config.txt -p wa -k port-redirect-config
sudo auditctl -w /etc/hosts -p wa -k hosts-modification
sudo auditctl -w /usr/local/bin/port-redirect-service -p x -k port-redirect-exec

# View audit logs
sudo ausearch -k port-redirect-config
sudo ausearch -k hosts-modification
sudo ausearch -k port-redirect-exec
```

#### Security Monitoring Script
```bash
#!/bin/bash
# security-monitor.sh - Monitor security events

LOG_FILE="/var/log/port-redirect-security.log"

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | sudo tee -a "$LOG_FILE"
}

check_process_integrity() {
    local expected_user="root"
    local actual_user=$(ps -o user= -p $(pgrep port-redirect-service) 2>/dev/null)
    
    if [[ "$actual_user" != "$expected_user" ]]; then
        log_event "SECURITY: Service running as unexpected user: $actual_user"
        return 1
    fi
    
    return 0
}

check_file_integrity() {
    local config_file="/etc/port-redirect/config.txt"
    local binary_file="/usr/local/bin/port-redirect-service"
    
    # Check configuration file permissions
    local config_perms=$(stat -c "%a" "$config_file" 2>/dev/null)
    if [[ "$config_perms" != "644" ]]; then
        log_event "SECURITY: Configuration file has incorrect permissions: $config_perms"
        return 1
    fi
    
    # Check binary permissions
    local binary_perms=$(stat -c "%a" "$binary_file" 2>/dev/null)
    if [[ "$binary_perms" != "755" ]]; then
        log_event "SECURITY: Binary file has incorrect permissions: $binary_perms"
        return 1
    fi
    
    return 0
}

check_network_binding() {
    # Verify service only binds to localhost
    local external_bindings=$(sudo netstat -tlnp | grep port-redirect-service | grep -v "127.0.0.1\|::1")
    
    if [[ -n "$external_bindings" ]]; then
        log_event "SECURITY: Service has external network bindings: $external_bindings"
        return 1
    fi
    
    return 0
}

# Run security checks
check_process_integrity
check_file_integrity  
check_network_binding

log_event "Security check completed"
```

### 2. Intrusion Detection

#### File Integrity Monitoring
```bash
# Create baseline checksums
sudo find /etc/port-redirect /usr/local/bin/port-redirect-service -type f -exec sha256sum {} \; > /var/log/port-redirect-baseline.sha256

# Check for changes
sudo sha256sum -c /var/log/port-redirect-baseline.sha256
```

#### Anomaly Detection
```bash
#!/bin/bash
# anomaly-detection.sh - Detect unusual service behavior

detect_anomalies() {
    # Check for unusual CPU usage
    local cpu_usage=$(ps -o %cpu= -p $(pgrep port-redirect-service) 2>/dev/null)
    if (( $(echo "$cpu_usage > 10.0" | bc -l) )); then
        echo "ANOMALY: High CPU usage: $cpu_usage%"
    fi
    
    # Check for unusual memory usage
    local mem_usage=$(ps -o %mem= -p $(pgrep port-redirect-service) 2>/dev/null)
    if (( $(echo "$mem_usage > 5.0" | bc -l) )); then
        echo "ANOMALY: High memory usage: $mem_usage%"
    fi
    
    # Check for unusual network activity
    local connections=$(sudo netstat -an | grep :80 | wc -l)
    if [[ "$connections" -gt 100 ]]; then
        echo "ANOMALY: High connection count: $connections"
    fi
}

detect_anomalies
```

## Incident Response

### 1. Security Incident Classification

#### Severity Levels

| Level | Description | Examples | Response Time |
|-------|-------------|----------|---------------|
| **CRITICAL** | System compromise | Unauthorized hosts modification | Immediate |
| **HIGH** | Service compromise | Malicious configuration | < 1 hour |
| **MEDIUM** | Suspicious activity | Unusual network patterns | < 4 hours |
| **LOW** | Policy violations | Permission changes | < 24 hours |

### 2. Incident Response Procedures

#### Immediate Response (CRITICAL/HIGH)
```bash
# 1. Stop the service immediately
sudo ./install.sh stop

# 2. Preserve evidence
sudo cp /etc/hosts /tmp/hosts-incident-$(date +%Y%m%d-%H%M%S)
sudo cp /etc/port-redirect/config.txt /tmp/config-incident-$(date +%Y%m%d-%H%M%S)

# 3. Restore from backup
sudo cp /etc/port-redirect/hosts.backup /etc/hosts

# 4. Check for persistence mechanisms
sudo find /etc /usr/local -name "*port-redirect*" -ls

# 5. Review logs
# macOS:
sudo tail -100 /var/log/port-redirect-service.log

# Linux:
sudo journalctl -u port-redirect --since "1 hour ago"
```

#### Investigation Steps
```bash
# 1. Check process tree
sudo ps auxf | grep -A5 -B5 port-redirect

# 2. Review network connections
sudo netstat -tlnp | grep port-redirect-service

# 3. Check file modifications
sudo find /etc /usr/local -name "*port-redirect*" -exec stat {} \;

# 4. Review system logs
sudo grep -i "port-redirect\|hosts" /var/log/syslog
sudo grep -i "port-redirect\|hosts" /var/log/auth.log

# 5. Check for unauthorized changes
sudo auditctl -l | grep port-redirect
sudo ausearch -k port-redirect-config --start recent
```

### 3. Recovery Procedures

#### Clean Reinstallation
```bash
# 1. Complete removal
sudo ./install.sh uninstall

# 2. Verify removal
sudo find / -name "*port-redirect*" 2>/dev/null

# 3. Clean installation
# Download fresh copy from trusted source
# Verify checksums
# Reinstall with: sudo ./install.sh install

# 4. Restore configuration from backup
sudo cp /path/to/trusted/config.txt /etc/port-redirect/config.txt

# 5. Verify installation
sudo ./install.sh status
curl -I http://localhost/status
```

#### Hardening After Incident
```bash
# 1. Enable additional monitoring
sudo auditctl -w /etc/port-redirect -p wa -k port-redirect-all
sudo auditctl -w /usr/local/bin/port-redirect-service -p x -k port-redirect-exec

# 2. Implement file integrity monitoring
sudo aide --init  # If AIDE is available
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 3. Review and tighten permissions
sudo chmod 600 /etc/port-redirect/config.txt  # More restrictive
sudo chattr +i /usr/local/bin/port-redirect-service  # Immutable (Linux)

# 4. Implement network monitoring
# Set up continuous monitoring of port 80 bindings
```

### 4. Prevention Measures

#### Proactive Security
```bash
# 1. Regular security audits
# Schedule weekly security checks
echo "0 2 * * 0 /usr/local/bin/security-monitor.sh" | sudo crontab -

# 2. Automated integrity checks
# Daily file integrity verification
echo "0 3 * * * sha256sum -c /var/log/port-redirect-baseline.sha256" | sudo crontab -

# 3. Log rotation and retention
# Ensure logs are preserved for forensic analysis
sudo logrotate -f /etc/logrotate.d/port-redirect
```

#### Security Updates
```bash
# 1. Keep system updated
sudo apt update && sudo apt upgrade  # Debian/Ubuntu
sudo yum update                      # RHEL/CentOS

# 2. Monitor for service updates
# Check repository for updates regularly
# Subscribe to security notifications

# 3. Review configuration regularly
# Monthly configuration review
# Validate all configured ports are still needed
```

## Conclusion

The Port Redirect Service, while requiring elevated privileges, implements multiple layers of security controls to minimize risk. Regular monitoring, proper configuration management, and incident response procedures are essential for maintaining security in production environments.

### Security Checklist

- [ ] Service runs with minimal required privileges
- [ ] Configuration file has proper permissions (644)
- [ ] Hosts file backup exists and is valid
- [ ] Network binding is localhost-only
- [ ] Audit logging is enabled
- [ ] File integrity monitoring is configured
- [ ] Incident response procedures are documented
- [ ] Regular security reviews are scheduled

For additional security questions or to report security issues, please follow responsible disclosure practices and contact the maintainers through appropriate channels.