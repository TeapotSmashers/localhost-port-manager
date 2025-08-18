#!/bin/bash

# macOS Installation Script for Port Redirect Service
# This script installs the port-redirect-service as a launchd daemon

set -e

# Configuration
SERVICE_NAME="com.portredirect.service"
PLIST_FILE="$SERVICE_NAME.plist"
LAUNCHD_DIR="/Library/LaunchDaemons"
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

# Function to check if service is already running
check_existing_service() {
    if launchctl list | grep -q "$SERVICE_NAME"; then
        print_warning "Service $SERVICE_NAME is already loaded"
        print_status "Stopping existing service..."
        launchctl unload "$LAUNCHD_DIR/$PLIST_FILE" 2>/dev/null || true
        sleep 2
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

# Function to install the launchd plist
install_plist() {
    print_status "Installing launchd plist to $LAUNCHD_DIR/$PLIST_FILE"
    
    # Check if plist file exists
    if [[ ! -f "$PLIST_FILE" ]]; then
        print_error "Plist file '$PLIST_FILE' not found in current directory"
        exit 1
    fi
    
    # Copy plist file
    cp "$PLIST_FILE" "$LAUNCHD_DIR/$PLIST_FILE"
    chmod 644 "$LAUNCHD_DIR/$PLIST_FILE"
    chown root:wheel "$LAUNCHD_DIR/$PLIST_FILE"
    
    print_status "Plist installed successfully"
}

# Function to load and start the service
start_service() {
    print_status "Loading and starting the service"
    
    # Load the service
    launchctl load "$LAUNCHD_DIR/$PLIST_FILE"
    
    # Wait a moment for the service to start
    sleep 3
    
    # Check if service is running
    if launchctl list | grep -q "$SERVICE_NAME"; then
        print_status "Service started successfully"
        print_status "Service status:"
        launchctl list | grep "$SERVICE_NAME" || true
    else
        print_error "Failed to start service"
        print_error "Check logs at $LOG_DIR/port-redirect-service.log for details"
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
    
    # Check if plist exists
    if [[ -f "$LAUNCHD_DIR/$PLIST_FILE" ]]; then
        print_status "✓ Launchd plist is installed"
    else
        print_error "✗ Launchd plist is not installed"
        return 1
    fi
    
    # Check if config directory exists
    if [[ -d "$CONFIG_DIR" ]]; then
        print_status "✓ Configuration directory exists"
    else
        print_error "✗ Configuration directory is missing"
        return 1
    fi
    
    # Check if service is loaded
    if launchctl list | grep -q "$SERVICE_NAME"; then
        print_status "✓ Service is loaded and running"
    else
        print_error "✗ Service is not running"
        return 1
    fi
    
    print_status "Installation verification completed successfully"
}

# Function to show usage information
show_usage() {
    echo "Usage: $0 [install|uninstall|status|start|stop|restart]"
    echo ""
    echo "Commands:"
    echo "  install   - Install the port redirect service"
    echo "  uninstall - Remove the port redirect service"
    echo "  status    - Show service status"
    echo "  start     - Start the service"
    echo "  stop      - Stop the service"
    echo "  restart   - Restart the service"
    echo ""
    echo "Note: This script must be run with sudo privileges"
}

# Function to uninstall the service
uninstall_service() {
    print_status "Uninstalling Port Redirect Service..."
    
    # Stop and unload the service
    if launchctl list | grep -q "$SERVICE_NAME"; then
        print_status "Stopping service..."
        launchctl unload "$LAUNCHD_DIR/$PLIST_FILE" 2>/dev/null || true
        sleep 2
    fi
    
    # Remove plist file
    if [[ -f "$LAUNCHD_DIR/$PLIST_FILE" ]]; then
        print_status "Removing plist file..."
        rm -f "$LAUNCHD_DIR/$PLIST_FILE"
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
    
    # Check if service is loaded
    if launchctl list | grep -q "$SERVICE_NAME"; then
        echo "Service Status: RUNNING"
        launchctl list | grep "$SERVICE_NAME"
    else
        echo "Service Status: NOT RUNNING"
    fi
    
    echo ""
    
    # Check binary
    if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
        echo "Binary: INSTALLED ($INSTALL_DIR/$BINARY_NAME)"
    else
        echo "Binary: NOT INSTALLED"
    fi
    
    # Check plist
    if [[ -f "$LAUNCHD_DIR/$PLIST_FILE" ]]; then
        echo "Plist: INSTALLED ($LAUNCHD_DIR/$PLIST_FILE)"
    else
        echo "Plist: NOT INSTALLED"
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
    if launchctl list | grep -q "$SERVICE_NAME"; then
        print_warning "Service is already running"
    else
        print_status "Starting service..."
        launchctl load "$LAUNCHD_DIR/$PLIST_FILE"
        sleep 2
        if launchctl list | grep -q "$SERVICE_NAME"; then
            print_status "Service started successfully"
        else
            print_error "Failed to start service"
        fi
    fi
}

# Function to stop the service
stop_service() {
    if launchctl list | grep -q "$SERVICE_NAME"; then
        print_status "Stopping service..."
        launchctl unload "$LAUNCHD_DIR/$PLIST_FILE"
        sleep 2
        print_status "Service stopped"
    else
        print_warning "Service is not running"
    fi
}

# Function to restart the service
restart_service() {
    print_status "Restarting service..."
    stop_service
    sleep 1
    start_service_only
}

# Main installation function
install_service() {
    print_status "Installing Port Redirect Service for macOS..."
    
    check_root
    check_existing_service
    install_binary
    create_config
    install_plist
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
    print_status "  sudo $0 uninstall - Remove the service"
    print_status ""
    print_status "Configuration file: $CONFIG_DIR/config.txt"
    print_status "Log files: $LOG_DIR/port-redirect-service.log"
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
    *)
        show_usage
        exit 1
        ;;
esac