#!/bin/bash

# Linux Installation Script for Port Redirect Service
# This script installs the port-redirect-service as a systemd service

set -e

# Configuration
SERVICE_NAME="port-redirect"
SERVICE_FILE="$SERVICE_NAME.service"
SYSTEMD_DIR="/etc/systemd/system"
BINARY_NAME="port-redirect-service"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/port-redirect"
LOG_DIR="/var/log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to check if systemd is available
check_systemd() {
    if ! command -v systemctl &> /dev/null; then
        print_error "systemctl not found. This script requires systemd."
        exit 1
    fi
    
    if ! systemctl --version &> /dev/null; then
        print_error "systemd is not running or not available"
        exit 1
    fi
}

# Function to check if service is already running
check_existing_service() {
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_warning "Service $SERVICE_NAME is already running"
        print_status "Stopping existing service..."
        systemctl stop "$SERVICE_NAME" || true
        sleep 2
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_warning "Service $SERVICE_NAME is already enabled"
        print_status "Disabling existing service..."
        systemctl disable "$SERVICE_NAME" || true
    fi
}

# Function to install the binary
install_binary() {
    print_status "Installing binary to $INSTALL_DIR/$BINARY_NAME"
    
    # Check if binary exists in current directory
    if [[ ! -f "$BINARY_NAME" ]]; then
        print_error "Binary '$BINARY_NAME' not found in current directory"
        print_error "Please build the binary first with: go build -o $BINARY_NAME"
        exit 1
    fi
    
    # Copy binary to install directory
    cp "$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    chmod 755 "$INSTALL_DIR/$BINARY_NAME"
    
    print_status "Binary installed successfully"
}

# Function to create configuration directory and default config
create_config() {
    print_status "Creating configuration directory: $CONFIG_DIR"
    mkdir -p "$CONFIG_DIR"
    
    # Create default config if it doesn't exist
    if [[ ! -f "$CONFIG_DIR/config.txt" ]]; then
        print_status "Creating default configuration file"
        cat > "$CONFIG_DIR/config.txt" << EOF
# Port Redirect Service Configuration
# One port per line, comments start with #
# Common development ports:

3000
8080
5173
9000
EOF
        chmod 644 "$CONFIG_DIR/config.txt"
        print_status "Default configuration created at $CONFIG_DIR/config.txt"
    else
        print_warning "Configuration file already exists at $CONFIG_DIR/config.txt"
    fi
}

# Function to install the systemd service file
install_service_file() {
    print_status "Installing systemd service file to $SYSTEMD_DIR/$SERVICE_FILE"
    
    # Check if service file exists
    if [[ ! -f "$SERVICE_FILE" ]]; then
        print_error "Service file '$SERVICE_FILE' not found in current directory"
        exit 1
    fi
    
    # Copy service file
    cp "$SERVICE_FILE" "$SYSTEMD_DIR/$SERVICE_FILE"
    chmod 644 "$SYSTEMD_DIR/$SERVICE_FILE"
    chown root:root "$SYSTEMD_DIR/$SERVICE_FILE"
    
    # Reload systemd daemon
    print_status "Reloading systemd daemon..."
    systemctl daemon-reload
    
    print_status "Service file installed successfully"
}

# Function to enable and start the service
start_service() {
    print_status "Enabling and starting the service"
    
    # Enable the service
    systemctl enable "$SERVICE_NAME"
    
    # Start the service
    systemctl start "$SERVICE_NAME"
    
    # Wait a moment for the service to start
    sleep 3
    
    # Check if service is running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Service started successfully"
        print_status "Service status:"
        systemctl status "$SERVICE_NAME" --no-pager -l || true
    else
        print_error "Failed to start service"
        print_error "Check logs with: journalctl -u $SERVICE_NAME -f"
        exit 1
    fi
}

# Function to verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    # Check if binary exists and is executable
    if [[ -x "$INSTALL_DIR/$BINARY_NAME" ]]; then
        print_status "✓ Binary is installed and executable"
    else
        print_error "✗ Binary is not properly installed"
        return 1
    fi
    
    # Check if service file exists
    if [[ -f "$SYSTEMD_DIR/$SERVICE_FILE" ]]; then
        print_status "✓ Systemd service file is installed"
    else
        print_error "✗ Systemd service file is not installed"
        return 1
    fi
    
    # Check if config directory exists
    if [[ -d "$CONFIG_DIR" ]]; then
        print_status "✓ Configuration directory exists"
    else
        print_error "✗ Configuration directory is missing"
        return 1
    fi
    
    # Check if service is enabled
    if systemctl is-enabled --quiet "$SERVICE_NAME"; then
        print_status "✓ Service is enabled"
    else
        print_error "✗ Service is not enabled"
        return 1
    fi
    
    # Check if service is active
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "✓ Service is active and running"
    else
        print_error "✗ Service is not running"
        return 1
    fi
    
    print_status "Installation verification completed successfully"
}

# Function to show usage information
show_usage() {
    echo "Usage: $0 [install|uninstall|status|start|stop|restart|enable|disable]"
    echo ""
    echo "Commands:"
    echo "  install   - Install the port redirect service"
    echo "  uninstall - Remove the port redirect service"
    echo "  status    - Show service status"
    echo "  start     - Start the service"
    echo "  stop      - Stop the service"
    echo "  restart   - Restart the service"
    echo "  enable    - Enable service to start at boot"
    echo "  disable   - Disable service from starting at boot"
    echo ""
    echo "Note: This script must be run with sudo privileges"
}

# Function to uninstall the service
uninstall_service() {
    print_status "Uninstalling Port Redirect Service..."
    
    # Stop the service if running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Stopping service..."
        systemctl stop "$SERVICE_NAME"
        sleep 2
    fi
    
    # Disable the service if enabled
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_status "Disabling service..."
        systemctl disable "$SERVICE_NAME"
    fi
    
    # Remove service file
    if [[ -f "$SYSTEMD_DIR/$SERVICE_FILE" ]]; then
        print_status "Removing service file..."
        rm -f "$SYSTEMD_DIR/$SERVICE_FILE"
        systemctl daemon-reload
    fi
    
    # Remove binary
    if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
        print_status "Removing binary..."
        rm -f "$INSTALL_DIR/$BINARY_NAME"
    fi
    
    # Ask about configuration removal
    echo -n "Remove configuration directory $CONFIG_DIR? [y/N]: "
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        print_status "Removing configuration directory..."
        rm -rf "$CONFIG_DIR"
    else
        print_status "Configuration directory preserved"
    fi
    
    print_status "Uninstallation completed"
}

# Function to show service status
show_status() {
    print_status "Port Redirect Service Status:"
    echo ""
    
    # Check if service is active
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "Service Status: RUNNING"
    else
        echo "Service Status: NOT RUNNING"
    fi
    
    # Check if service is enabled
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo "Boot Status: ENABLED"
    else
        echo "Boot Status: DISABLED"
    fi
    
    echo ""
    
    # Show detailed status
    systemctl status "$SERVICE_NAME" --no-pager -l || echo "Service not found"
    
    echo ""
    
    # Check binary
    if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
        echo "Binary: INSTALLED ($INSTALL_DIR/$BINARY_NAME)"
    else
        echo "Binary: NOT INSTALLED"
    fi
    
    # Check service file
    if [[ -f "$SYSTEMD_DIR/$SERVICE_FILE" ]]; then
        echo "Service File: INSTALLED ($SYSTEMD_DIR/$SERVICE_FILE)"
    else
        echo "Service File: NOT INSTALLED"
    fi
    
    # Check config
    if [[ -f "$CONFIG_DIR/config.txt" ]]; then
        echo "Config: EXISTS ($CONFIG_DIR/config.txt)"
        echo "Configured ports:"
        grep -v '^#' "$CONFIG_DIR/config.txt" | grep -v '^$' | sed 's/^/  - /' || echo "  (no ports configured)"
    else
        echo "Config: NOT FOUND"
    fi
}

# Function to start the service
start_service_only() {
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_warning "Service is already running"
    else
        print_status "Starting service..."
        systemctl start "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_status "Service started successfully"
        else
            print_error "Failed to start service"
            print_error "Check logs with: journalctl -u $SERVICE_NAME -f"
        fi
    fi
}

# Function to stop the service
stop_service() {
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Stopping service..."
        systemctl stop "$SERVICE_NAME"
        sleep 2
        print_status "Service stopped"
    else
        print_warning "Service is not running"
    fi
}

# Function to restart the service
restart_service() {
    print_status "Restarting service..."
    systemctl restart "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Service restarted successfully"
    else
        print_error "Failed to restart service"
        print_error "Check logs with: journalctl -u $SERVICE_NAME -f"
    fi
}

# Function to enable the service
enable_service() {
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_warning "Service is already enabled"
    else
        print_status "Enabling service..."
        systemctl enable "$SERVICE_NAME"
        print_status "Service enabled successfully"
    fi
}

# Function to disable the service
disable_service() {
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_status "Disabling service..."
        systemctl disable "$SERVICE_NAME"
        print_status "Service disabled successfully"
    else
        print_warning "Service is not enabled"
    fi
}

# Main installation function
install_service() {
    print_status "Installing Port Redirect Service for Linux (systemd)..."
    
    check_root
    check_systemd
    check_existing_service
    install_binary
    create_config
    install_service_file
    start_service
    verify_installation
    
    print_status ""
    print_status "Installation completed successfully!"
    print_status ""
    print_status "Service management commands:"
    print_status "  sudo $0 status    - Show service status"
    print_status "  sudo $0 start     - Start the service"
    print_status "  sudo $0 stop      - Stop the service"
    print_status "  sudo $0 restart   - Restart the service"
    print_status "  sudo $0 enable    - Enable service at boot"
    print_status "  sudo $0 disable   - Disable service at boot"
    print_status "  sudo $0 uninstall - Remove the service"
    print_status ""
    print_status "Configuration file: $CONFIG_DIR/config.txt"
    print_status "View logs: journalctl -u $SERVICE_NAME -f"
    print_status "Status page: http://localhost/status"
}

# Main script logic
case "${1:-install}" in
    install)
        install_service
        ;;
    uninstall)
        check_root
        uninstall_service
        ;;
    status)
        show_status
        ;;
    start)
        check_root
        start_service_only
        ;;
    stop)
        check_root
        stop_service
        ;;
    restart)
        check_root
        restart_service
        ;;
    enable)
        check_root
        enable_service
        ;;
    disable)
        check_root
        disable_service
        ;;
    *)
        show_usage
        exit 1
        ;;
esac