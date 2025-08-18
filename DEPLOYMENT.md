# Deployment Guide

This guide covers deployment scenarios for both Local Mode and Web Service Mode of the Port Redirect Service.

## Table of Contents

- [Local Mode Deployment](#local-mode-deployment)
- [Web Service Mode Deployment](#web-service-mode-deployment)
- [Configuration Management](#configuration-management)
- [Security Considerations](#security-considerations)
- [Monitoring and Maintenance](#monitoring-and-maintenance)
- [Troubleshooting](#troubleshooting)

## Local Mode Deployment

### Prerequisites

- Go 1.19+ (for building from source)
- Root/Administrator privileges
- Port 80 available
- Write access to `/etc/hosts`

### Installation Steps

1. **Build the service:**
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

4. **Test functionality:**
   ```bash
   curl -I http://3000.local
   ```

### Local Mode Configuration

```bash
# /etc/port-redirect/config.txt
# Local mode configuration (default)

# Development ports
3000    # React/Next.js
8080    # Backend services
5173    # Vite dev server
4200    # Angular CLI

# Local mode is default - no additional configuration needed
```

## Web Service Mode Deployment

### Prerequisites

- Go 1.19+ (for building from source)
- Server with public IP address
- Domain name with DNS control
- Firewall configuration access
- Standard user privileges (root not required for web service mode)

### Deployment Architecture

```
Internet
    ↓
DNS (*.yourdomain.com → Server IP)
    ↓
Firewall (Allow port 8080)
    ↓
Port Redirect Service (Server:8080)
    ↓
Local Services (localhost:3000, localhost:8080, etc.)
```

### Step-by-Step Web Service Deployment

#### 1. Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y  # Ubuntu/Debian
# or
sudo yum update -y  # CentOS/RHEL

# Install Go (if not already installed)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### 2. Build and Install Service

```bash
# Clone or copy source code to server
git clone <repository-url>
cd port-redirect-service

# Build the service
go build -o port-redirect-service

# Install the service
sudo ./install.sh install
```

#### 3. Configure Web Service Mode

```bash
# Create web service configuration
sudo tee /etc/port-redirect/config.txt << EOF
# Application ports
3000    # Frontend application
8000    # Main API
8001    # Auth service
8002    # File service

# Web service mode configuration
mode=web
web_port=8080
domain_patterns=*.yourdomain.com,*.dev.yourdomain.com

# Security settings
enable_rate_limit=true
rate_limit_rps=100
EOF
```

#### 4. DNS Configuration

Configure DNS records with your domain provider:

```bash
# Wildcard A record (recommended)
Type: A
Name: *.yourdomain.com
Value: YOUR_SERVER_IP
TTL: 300

# Alternative: Individual records
Type: A
Name: 3000.yourdomain.com
Value: YOUR_SERVER_IP

Type: A
Name: 8000.yourdomain.com
Value: YOUR_SERVER_IP
```

#### 5. Firewall Configuration

##### Ubuntu/Debian (ufw)
```bash
# Enable firewall
sudo ufw enable

# Allow SSH (important!)
sudo ufw allow ssh

# Allow web service port
sudo ufw allow 8080/tcp

# Check status
sudo ufw status
```

##### CentOS/RHEL (firewalld)
```bash
# Enable firewall
sudo systemctl enable firewalld
sudo systemctl start firewalld

# Allow web service port
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload

# Check status
sudo firewall-cmd --list-all
```

#### 6. Start and Verify Service

```bash
# Start the service
sudo ./install.sh start

# Check status
sudo ./install.sh status

# Verify web service is listening
sudo netstat -tlnp | grep :8080

# Test locally
curl -I -H "Host: 3000.yourdomain.com" http://localhost:8080

# Test externally (from another machine)
curl -I http://3000.yourdomain.com
```

### Production Web Service Configuration

For production deployments, use enhanced security settings:

```bash
# /etc/port-redirect/config.txt
# Production web service configuration

# Production ports
3000    # Frontend
8000    # API Gateway
8001    # User Service
8002    # Payment Service

# Web service mode
mode=web
web_port=80
domain_patterns=*.prod.company.com

# Enhanced security
enable_rate_limit=true
rate_limit_rps=50
```

### Load Balancer Integration

#### Nginx Reverse Proxy
```nginx
# /etc/nginx/sites-available/port-redirect
upstream port_redirect {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name *.yourdomain.com;
    
    location / {
        proxy_pass http://port_redirect;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    location /health {
        proxy_pass http://port_redirect/health;
        access_log off;
    }
}
```

#### HAProxy Configuration
```
# /etc/haproxy/haproxy.cfg
frontend port_redirect_frontend
    bind *:80
    default_backend port_redirect_backend

backend port_redirect_backend
    balance roundrobin
    option httpchk GET /health
    server port_redirect1 127.0.0.1:8080 check
```

## Configuration Management

### Environment-Based Configuration

#### Development Environment
```bash
# /etc/port-redirect/config.txt
# Development environment

3000    # Dev frontend
8000    # Dev API

mode=web
web_port=8080
domain_patterns=*.dev.company.com

enable_rate_limit=false
```

#### Staging Environment
```bash
# /etc/port-redirect/config.txt
# Staging environment

3100    # Staging frontend
8100    # Staging API

mode=web
web_port=8080
domain_patterns=*.staging.company.com

enable_rate_limit=true
rate_limit_rps=200
```

#### Production Environment
```bash
# /etc/port-redirect/config.txt
# Production environment

3000    # Prod frontend
8000    # Prod API

mode=web
web_port=80
domain_patterns=*.company.com

enable_rate_limit=true
rate_limit_rps=50
```

### Configuration Automation

#### Ansible Playbook Example
```yaml
# deploy-port-redirect.yml
---
- hosts: web_servers
  become: yes
  vars:
    deployment_mode: web
    web_port: 8080
    domain_patterns: "*.{{ domain_name }}"
    
  tasks:
    - name: Create configuration directory
      file:
        path: /etc/port-redirect
        state: directory
        mode: '0755'
    
    - name: Deploy configuration
      template:
        src: config.txt.j2
        dest: /etc/port-redirect/config.txt
        mode: '0644'
      notify: restart port-redirect
    
    - name: Install service
      shell: ./install.sh install
      args:
        chdir: /opt/port-redirect-service
    
  handlers:
    - name: restart port-redirect
      shell: ./install.sh restart
      args:
        chdir: /opt/port-redirect-service
```

#### Docker Deployment
```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go build -o port-redirect-service

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/port-redirect-service .
COPY config.txt /etc/port-redirect/config.txt

EXPOSE 8080
CMD ["./port-redirect-service"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  port-redirect:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config.txt:/etc/port-redirect/config.txt:ro
    environment:
      - LOG_LEVEL=INFO
    restart: unless-stopped
```

## Security Considerations

### Network Security

#### Firewall Rules
```bash
# Restrictive firewall (recommended for production)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 8080/tcp
sudo ufw enable
```

#### Rate Limiting
```bash
# Configure appropriate rate limits based on usage
# Development: 200+ RPS
# Staging: 100-200 RPS  
# Production: 50-100 RPS

# Monitor rate limiting effectiveness
curl http://your-server:8080/status?format=json | jq '.web_service_metrics.rate_limited_requests'
```

### Access Control

#### IP Whitelisting (if needed)
```bash
# Allow only specific IP ranges
sudo ufw allow from 192.168.1.0/24 to any port 8080
sudo ufw allow from 10.0.0.0/8 to any port 8080
```

#### Domain Validation
```bash
# Use specific domain patterns instead of wildcards when possible
domain_patterns=3000.company.com,8000.company.com,5173.company.com
```

### SSL/TLS Termination

For production deployments, use SSL/TLS termination at the load balancer or reverse proxy level:

```nginx
# Nginx with SSL
server {
    listen 443 ssl;
    server_name *.yourdomain.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

## Monitoring and Maintenance

### Health Monitoring

#### Basic Health Check
```bash
#!/bin/bash
# health-check.sh

SERVICE_URL="http://localhost:8080/health"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL")

if [ "$RESPONSE" = "200" ]; then
    echo "Service is healthy"
    exit 0
else
    echo "Service is unhealthy (HTTP $RESPONSE)"
    exit 1
fi
```

#### Comprehensive Monitoring Script
```bash
#!/bin/bash
# monitor-service.sh

SERVICE_URL="http://localhost:8080"
LOG_FILE="/var/log/port-redirect-monitor.log"

check_service() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Check health endpoint
    local health_status=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/health")
    
    # Get service metrics
    local metrics=$(curl -s "$SERVICE_URL/status?format=json")
    local request_count=$(echo "$metrics" | jq -r '.web_service_metrics.request_count // 0')
    local failed_requests=$(echo "$metrics" | jq -r '.web_service_metrics.failed_requests // 0')
    
    # Log status
    echo "[$timestamp] Health: $health_status, Requests: $request_count, Failed: $failed_requests" >> "$LOG_FILE"
    
    # Alert on issues
    if [ "$health_status" != "200" ]; then
        echo "[$timestamp] ALERT: Service unhealthy" >> "$LOG_FILE"
        # Send alert (email, Slack, etc.)
    fi
}

# Run check
check_service
```

### Log Management

#### Log Rotation Configuration
```bash
# /etc/logrotate.d/port-redirect
/var/log/port-redirect-service.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        sudo ./install.sh restart > /dev/null 2>&1 || true
    endscript
}
```

### Performance Monitoring

#### Metrics Collection
```bash
#!/bin/bash
# collect-metrics.sh

METRICS_URL="http://localhost:8080/status?format=json"
METRICS_FILE="/var/log/port-redirect-metrics.json"

# Collect metrics
curl -s "$METRICS_URL" >> "$METRICS_FILE"
echo "" >> "$METRICS_FILE"

# Optional: Send to monitoring system
# curl -X POST -H "Content-Type: application/json" \
#      -d @<(curl -s "$METRICS_URL") \
#      "https://your-monitoring-system/api/metrics"
```

## Troubleshooting

### Common Deployment Issues

#### Service Won't Start
```bash
# Check configuration syntax
sudo ./install.sh validate

# Check port availability
sudo lsof -i :8080

# Check logs
journalctl -u port-redirect -f

# Test configuration manually
./port-redirect-service -config /etc/port-redirect/config.txt -test
```

#### DNS Issues
```bash
# Test DNS resolution
dig 3000.yourdomain.com
nslookup 3000.yourdomain.com

# Test from different locations
# Use online DNS checkers or different servers
```

#### Firewall Issues
```bash
# Check firewall status
sudo ufw status verbose

# Test port connectivity
telnet your-server-ip 8080

# Check service binding
sudo netstat -tlnp | grep :8080
```

### Performance Issues

#### High CPU Usage
```bash
# Check service resource usage
top -p $(pgrep port-redirect-service)

# Check request volume
curl http://localhost:8080/status?format=json | jq '.web_service_metrics.request_count'

# Consider rate limiting adjustment
```

#### Memory Leaks
```bash
# Monitor memory usage over time
ps -o pid,vsz,rss,comm -p $(pgrep port-redirect-service)

# Check rate limiter cleanup
curl http://localhost:8080/status?format=json | jq '.web_service_metrics.unique_ips'
```

### Recovery Procedures

#### Service Recovery
```bash
# Restart service
sudo ./install.sh restart

# If restart fails, reinstall
sudo ./install.sh uninstall
sudo ./install.sh install

# Check configuration backup
ls -la /etc/port-redirect/config.txt.backup.*
```

#### Configuration Recovery
```bash
# Restore from backup
sudo cp /etc/port-redirect/config.txt.backup.$(date +%Y%m%d) /etc/port-redirect/config.txt

# Reset to defaults
sudo ./install.sh uninstall
sudo rm -rf /etc/port-redirect/
sudo ./install.sh install
```

This deployment guide provides comprehensive instructions for both Local Mode and Web Service Mode deployments, covering everything from basic installation to production-ready configurations with monitoring and security considerations.