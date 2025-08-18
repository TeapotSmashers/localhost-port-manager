#!/bin/bash

# Unified Installation Script for Port Redirect Service
# This script automatically detects the platform and installs the service accordingly
# Supports: macOS (launchd) and Linux (systemd)

set -e

# Configuration
BINARY_NAME="port-redirect-service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

print_header() {
    echo -e "${BLUE}[HEADER]${NC} $1"
}

# Function to detect the operating system
detect_platform() {
    local os_name
    os_name=$(uname -s)
    
    case "$os_name" in
        Darwin*)
            echo "macos"
            ;;
        Linux*)
            echo "linux"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        print_error "Example: sudo $0 install"
        exit 1
    fi
}

# Function to validate binary exists
validate_binary() {
    if [[ ! -f "$SCRIPT_DIR/$BINARY_NAME" ]]; then
        print_error "Binary '$BINARY_NAME' not found in script directory"
        print_error "Please build the binary first with: go build -o $BINARY_NAME"
        print_error "Expected location: $SCRIPT_DIR/$BINARY_NAME"
        exit 1
    fi
    
    # Check if binary is executable
    if [[ ! -x "$SCRIPT_DIR/$BINARY_NAME" ]]; then
        print_warning "Binary is not executable, making it executable..."
        chmod +x "$SCRIPT_DIR/$BINARY_NAME"
    fi
    
    print_status "Binary validation passed: $SCRIPT_DIR/$BINARY_NAME"
}

# Function to validate platform-specific files
validate_platform_files() {
    local platform="$1"
    
    case "$platform" in
        macos)
            if [[ ! -f "$SCRIPT_DIR/scripts/macos/com.portredirect.service.plist" ]]; then
                print_error "macOS plist file not found: scripts/macos/com.portredirect.service.plist"
                exit 1
            fi
            if [[ ! -f "$SCRIPT_DIR/scripts/macos/install.sh" ]]; then
                print_error "macOS install script not found: scripts/macos/install.sh"
                exit 1
            fi
            ;;
        linux)
            if [[ ! -f "$SCRIPT_DIR/scripts/linux/port-redirect.service" ]]; then
                print_error "Linux service file not found: scripts/linux/port-redirect.service"
                exit 1
            fi
            if [[ ! -f "$SCRIPT_DIR/scripts/linux/install.sh" ]]; then
                print_error "Linux install script not found: scripts/linux/install.sh"
                exit 1
            fi
            ;;
    esac
    
    print_status "Platform-specific files validation passed"
}

# Function to create backup of important files before installation
create_installation_backup() {
    local backup_dir="/tmp/port-redirect-backup-$(date +%Y%m%d-%H%M%S)"
    
    print_status "Creating installation backup at: $backup_dir"
    mkdir -p "$backup_dir"
    
    # Backup hosts file if it exists
    if [[ -f "/etc/hosts" ]]; then
        cp "/etc/hosts" "$backup_dir/hosts.backup"
        print_status "Backed up /etc/hosts"
    fi
    
    # Store backup location for potential rollback
    echo "$backup_dir" > "/tmp/port-redirect-last-backup"
    
    print_status "Backup created successfully"
}

# Function to rollback installation on failure
rollback_installation() {
    local backup_dir
    
    if [[ -f "/tmp/port-redirect-last-backup" ]]; then
        backup_dir=$(cat "/tmp/port-redirect-last-backup")
        
        if [[ -d "$backup_dir" ]]; then
            print_warning "Rolling back installation..."
            
            # Restore hosts file if backup exists
            if [[ -f "$backup_dir/hosts.backup" ]]; then
                cp "$backup_dir/hosts.backup" "/etc/hosts"
                print_status "Restored /etc/hosts from backup"
            fi
            
            print_status "Rollback completed"
        fi
    fi
}

# Function to install on macOS
install_macos() {
    print_header "Installing Port Redirect Service on macOS (launchd)"
    
    local macos_script="$SCRIPT_DIR/scripts/macos/install.sh"
    local macos_plist="$SCRIPT_DIR/scripts/macos/com.portredirect.service.plist"
    
    # Copy files to temporary directory for installation
    local temp_dir=$(mktemp -d)
    cp "$SCRIPT_DIR/$BINARY_NAME" "$temp_dir/"
    cp "$macos_plist" "$temp_dir/"
    
    # Make install script executable
    chmod +x "$macos_script"
    
    # Change to temp directory and run installation
    pushd "$temp_dir" > /dev/null
    
    # Run the macOS-specific installation script
    if "$macos_script" install; then
        print_status "macOS installation completed successfully"
    else
        print_error "macOS installation failed"
        popd > /dev/null
        rm -rf "$temp_dir"
        return 1
    fi
    
    popd > /dev/null
    rm -rf "$temp_dir"
    
    return 0
}

# Function to install on Linux
install_linux() {
    print_header "Installing Port Redirect Service on Linux (systemd)"
    
    local linux_script="$SCRIPT_DIR/scripts/linux/install.sh"
    local linux_service="$SCRIPT_DIR/scripts/linux/port-redirect.service"
    
    # Copy files to temporary directory for installation
    local temp_dir=$(mktemp -d)
    cp "$SCRIPT_DIR/$BINARY_NAME" "$temp_dir/"
    cp "$linux_service" "$temp_dir/"
    
    # Make install script executable
    chmod +x "$linux_script"
    
    # Change to temp directory and run installation
    pushd "$temp_dir" > /dev/null
    
    # Run the Linux-specific installation script
    if "$linux_script" install; then
        print_status "Linux installation completed successfully"
    else
        print_error "Linux installation failed"
        popd > /dev/null
        rm -rf "$temp_dir"
        return 1
    fi
    
    popd > /dev/null
    rm -rf "$temp_dir"
    
    return 0
}

# Function to uninstall from macOS
uninstall_macos() {
    print_header "Uninstalling Port Redirect Service from macOS"
    
    local macos_script="$SCRIPT_DIR/scripts/macos/install.sh"
    
    if [[ -f "$macos_script" ]]; then
        chmod +x "$macos_script"
        "$macos_script" uninstall
    else
        print_error "macOS uninstall script not found"
        return 1
    fi
}

# Function to uninstall from Linux
uninstall_linux() {
    print_header "Uninstalling Port Redirect Service from Linux"
    
    local linux_script="$SCRIPT_DIR/scripts/linux/install.sh"
    
    if [[ -f "$linux_script" ]]; then
        chmod +x "$linux_script"
        "$linux_script" uninstall
    else
        print_error "Linux uninstall script not found"
        return 1
    fi
}

# Function to show service status
show_status() {
    local platform
    platform=$(detect_platform)
    
    case "$platform" in
        macos)
            local macos_script="$SCRIPT_DIR/scripts/macos/install.sh"
            if [[ -f "$macos_script" ]]; then
                chmod +x "$macos_script"
                "$macos_script" status
            else
                print_error "macOS status script not found"
            fi
            ;;
        linux)
            local linux_script="$SCRIPT_DIR/scripts/linux/install.sh"
            if [[ -f "$linux_script" ]]; then
                chmod +x "$linux_script"
                "$linux_script" status
            else
                print_error "Linux status script not found"
            fi
            ;;
        *)
            print_error "Unsupported platform for status check"
            ;;
    esac
}

# Function to manage service (start/stop/restart)
manage_service() {
    local action="$1"
    local platform
    platform=$(detect_platform)
    
    case "$platform" in
        macos)
            local macos_script="$SCRIPT_DIR/scripts/macos/install.sh"
            if [[ -f "$macos_script" ]]; then
                chmod +x "$macos_script"
                "$macos_script" "$action"
            else
                print_error "macOS management script not found"
            fi
            ;;
        linux)
            local linux_script="$SCRIPT_DIR/scripts/linux/install.sh"
            if [[ -f "$linux_script" ]]; then
                chmod +x "$linux_script"
                "$linux_script" "$action"
            else
                print_error "Linux management script not found"
            fi
            ;;
        *)
            print_error "Unsupported platform for service management"
            ;;
    esac
}

# Function to show usage information
show_usage() {
    echo "Port Redirect Service - Unified Installation Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install   - Install the port redirect service (default)"
    echo "  uninstall - Remove the port redirect service"
    echo "  status    - Show service status"
    echo "  start     - Start the service"
    echo "  stop      - Stop the service"
    echo "  restart   - Restart the service"
    echo "  validate  - Validate installation files without installing"
    echo ""
    echo "Platform Support:"
    echo "  ✓ macOS (launchd)"
    echo "  ✓ Linux (systemd)"
    echo ""
    echo "Requirements:"
    echo "  - Must be run with sudo privileges (except for status and validate)"
    echo "  - Binary must be built: go build -o $BINARY_NAME"
    echo ""
    echo "Examples:"
    echo "  sudo $0 install    # Install the service"
    echo "  sudo $0 status     # Check service status"
    echo "  sudo $0 uninstall  # Remove the service"
}

# Function to validate installation without installing
validate_installation() {
    local platform
    platform=$(detect_platform)
    
    print_header "Validating installation files for $platform"
    
    # Validate binary
    validate_binary
    
    # Validate platform-specific files
    validate_platform_files "$platform"
    
    print_status "All validation checks passed!"
    print_status "Platform: $platform"
    print_status "Ready for installation with: sudo $0 install"
}

# Main installation function
install_service() {
    local platform
    platform=$(detect_platform)
    
    print_header "Port Redirect Service - Unified Installer"
    print_status "Detected platform: $platform"
    
    # Validate platform support
    case "$platform" in
        macos|linux)
            print_status "Platform is supported"
            ;;
        *)
            print_error "Unsupported platform: $platform"
            print_error "This installer supports macOS and Linux only"
            exit 1
            ;;
    esac
    
    # Check root privileges
    check_root
    
    # Validate files before installation
    validate_binary
    validate_platform_files "$platform"
    
    # Create backup before installation
    create_installation_backup
    
    # Install based on platform
    case "$platform" in
        macos)
            if install_macos; then
                print_status ""
                print_status "🎉 Installation completed successfully on macOS!"
            else
                print_error "Installation failed on macOS"
                rollback_installation
                exit 1
            fi
            ;;
        linux)
            if install_linux; then
                print_status ""
                print_status "🎉 Installation completed successfully on Linux!"
            else
                print_error "Installation failed on Linux"
                rollback_installation
                exit 1
            fi
            ;;
    esac
    
    # Show post-installation information
    print_status ""
    print_status "Service Management:"
    print_status "  sudo $0 status    - Check service status"
    print_status "  sudo $0 start     - Start the service"
    print_status "  sudo $0 stop      - Stop the service"
    print_status "  sudo $0 restart   - Restart the service"
    print_status "  sudo $0 uninstall - Remove the service"
    print_status ""
    print_status "Configuration: /etc/port-redirect/config.txt"
    print_status "Status page: http://localhost/status"
    print_status ""
    print_status "The service is now running and will start automatically on boot."
}

# Function to uninstall service
uninstall_service() {
    local platform
    platform=$(detect_platform)
    
    print_header "Port Redirect Service - Uninstaller"
    print_status "Detected platform: $platform"
    
    check_root
    
    case "$platform" in
        macos)
            uninstall_macos
            ;;
        linux)
            uninstall_linux
            ;;
        *)
            print_error "Unsupported platform: $platform"
            exit 1
            ;;
    esac
}

# Trap to handle script interruption
trap 'print_error "Installation interrupted"; rollback_installation; exit 1' INT TERM

# Main script logic
case "${1:-install}" in
    install)
        install_service
        ;;
    uninstall)
        uninstall_service
        ;;
    status)
        show_status
        ;;
    start|stop|restart)
        check_root
        manage_service "$1"
        ;;
    validate)
        validate_installation
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_usage
        exit 1
        ;;
esac