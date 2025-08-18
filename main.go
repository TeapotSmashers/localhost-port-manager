package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Config holds the service configuration
type Config struct {
	Ports           []int
	ConfigFilePath  string
	HostsBackupPath string
	LogLevel        string
}

// PortRedirectService is the main service struct
type PortRedirectService struct {
	server           *http.Server
	config           *Config
	hostsManager     *HostsManager
	logger           *log.Logger
	structuredLogger *StructuredLogger
	logFileManager   *LogFileManager
	configWatcher    *ConfigWatcher
	startTime        time.Time
	configLoaded     time.Time
	lastError        string
}

// HostsManager manages /etc/hosts file entries
type HostsManager struct {
	hostsFilePath  string
	backupPath     string
	managedEntries []string
}

// NewHostsManager creates a new HostsManager instance
func NewHostsManager(hostsFilePath, backupPath string) *HostsManager {
	return &HostsManager{
		hostsFilePath:  hostsFilePath,
		backupPath:     backupPath,
		managedEntries: make([]string, 0),
	}
}

// CreateBackup creates a backup of the original hosts file
func (hm *HostsManager) CreateBackup() error {
	// Check if hosts file exists
	if _, err := os.Stat(hm.hostsFilePath); os.IsNotExist(err) {
		return fmt.Errorf("hosts file does not exist: %s", hm.hostsFilePath)
	}

	// Check if backup already exists
	if _, err := os.Stat(hm.backupPath); err == nil {
		// Backup already exists, don't overwrite
		return nil
	}

	// Create backup directory if it doesn't exist
	backupDir := filepath.Dir(hm.backupPath)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Read original hosts file
	originalContent, err := os.ReadFile(hm.hostsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	// Write backup file
	if err := os.WriteFile(hm.backupPath, originalContent, 0644); err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}

	return nil
}

// RestoreBackup restores the hosts file from backup
func (hm *HostsManager) RestoreBackup() error {
	// Check if backup exists
	if _, err := os.Stat(hm.backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", hm.backupPath)
	}

	// Read backup content
	backupContent, err := os.ReadFile(hm.backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Write backup content to hosts file
	if err := os.WriteFile(hm.hostsFilePath, backupContent, 0644); err != nil {
		return fmt.Errorf("failed to restore hosts file: %w", err)
	}

	return nil
}

// BackupExists checks if a backup file exists
func (hm *HostsManager) BackupExists() bool {
	_, err := os.Stat(hm.backupPath)
	return err == nil
}

// AddPortEntries adds port-based entries to /etc/hosts for the given ports
func (hm *HostsManager) AddPortEntries(ports []int) error {
	// Read current hosts file content
	content, err := os.ReadFile(hm.hostsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	lines := strings.Split(string(content), "\n")

	// Remove existing managed section if it exists
	lines = hm.removeManagedSection(lines)

	// Generate new entries for the ports
	newEntries := hm.generatePortEntries(ports)

	// Add managed section with new entries
	if len(newEntries) > 0 {
		managedSection := []string{
			"# BEGIN PORT-REDIRECT-SERVICE",
		}
		managedSection = append(managedSection, newEntries...)
		managedSection = append(managedSection, "# END PORT-REDIRECT-SERVICE")

		// Add managed section to the end of the file
		lines = append(lines, managedSection...)
	}

	// Write updated content back to hosts file
	updatedContent := strings.Join(lines, "\n")
	if err := os.WriteFile(hm.hostsFilePath, []byte(updatedContent), 0644); err != nil {
		return fmt.Errorf("failed to write hosts file: %w", err)
	}

	// Update managed entries list
	hm.managedEntries = newEntries

	return nil
}

// RemovePortEntries removes all managed entries from /etc/hosts
func (hm *HostsManager) RemovePortEntries() error {
	// Read current hosts file content
	content, err := os.ReadFile(hm.hostsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	lines := strings.Split(string(content), "\n")

	// Remove managed section
	lines = hm.removeManagedSection(lines)

	// Write updated content back to hosts file
	updatedContent := strings.Join(lines, "\n")
	if err := os.WriteFile(hm.hostsFilePath, []byte(updatedContent), 0644); err != nil {
		return fmt.Errorf("failed to write hosts file: %w", err)
	}

	// Clear managed entries list
	hm.managedEntries = nil

	return nil
}

// UpdatePortEntries updates the hosts file entries when configuration changes
func (hm *HostsManager) UpdatePortEntries(newPorts []int) error {
	return hm.AddPortEntries(newPorts)
}

// removeManagedSection removes the managed section from hosts file lines
func (hm *HostsManager) removeManagedSection(lines []string) []string {
	var result []string
	inManagedSection := false

	for _, line := range lines {
		if strings.TrimSpace(line) == "# BEGIN PORT-REDIRECT-SERVICE" {
			inManagedSection = true
			continue
		}
		if strings.TrimSpace(line) == "# END PORT-REDIRECT-SERVICE" {
			inManagedSection = false
			continue
		}
		if !inManagedSection {
			result = append(result, line)
		}
	}

	return result
}

// generatePortEntries generates hosts file entries for the given ports
func (hm *HostsManager) generatePortEntries(ports []int) []string {
	var entries []string
	tlds := []string{"local", "dev", "test", "localhost"}

	for _, port := range ports {
		for _, tld := range tlds {
			entry := fmt.Sprintf("%d.%s 127.0.0.1", port, tld)
			entries = append(entries, entry)
		}
	}

	return entries
}

// ValidateEntries checks if the hosts file contains the expected entries
func (hm *HostsManager) ValidateEntries(expectedPorts []int) (bool, []string, []string) {
	content, err := os.ReadFile(hm.hostsFilePath)
	if err != nil {
		return false, nil, []string{fmt.Sprintf("Failed to read hosts file: %v", err)}
	}

	lines := strings.Split(string(content), "\n")

	// Extract current managed entries
	currentEntries := hm.extractManagedEntries(lines)
	expectedEntries := hm.generatePortEntries(expectedPorts)

	// Find missing and extra entries
	missingEntries := hm.findMissingEntries(expectedEntries, currentEntries)
	extraEntries := hm.findExtraEntries(expectedEntries, currentEntries)

	isValid := len(missingEntries) == 0 && len(extraEntries) == 0

	return isValid, missingEntries, extraEntries
}

// extractManagedEntries extracts entries from the managed section
func (hm *HostsManager) extractManagedEntries(lines []string) []string {
	var entries []string
	inManagedSection := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "# BEGIN PORT-REDIRECT-SERVICE" {
			inManagedSection = true
			continue
		}
		if trimmedLine == "# END PORT-REDIRECT-SERVICE" {
			inManagedSection = false
			continue
		}
		if inManagedSection && trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") {
			entries = append(entries, trimmedLine)
		}
	}

	return entries
}

// findMissingEntries finds entries that should be present but are not
func (hm *HostsManager) findMissingEntries(expected, current []string) []string {
	currentMap := make(map[string]bool)
	for _, entry := range current {
		currentMap[entry] = true
	}

	var missing []string
	for _, entry := range expected {
		if !currentMap[entry] {
			missing = append(missing, entry)
		}
	}

	return missing
}

// findExtraEntries finds entries that are present but should not be
func (hm *HostsManager) findExtraEntries(expected, current []string) []string {
	expectedMap := make(map[string]bool)
	for _, entry := range expected {
		expectedMap[entry] = true
	}

	var extra []string
	for _, entry := range current {
		if !expectedMap[entry] {
			extra = append(extra, entry)
		}
	}

	return extra
}

// ServiceStatus represents the current status of the service
type ServiceStatus struct {
	Uptime          time.Duration   `json:"uptime"`
	ConfigLoaded    time.Time       `json:"config_loaded"`
	PortsConfigured []int           `json:"ports_configured"`
	HostsStatus     HostsFileStatus `json:"hosts_status"`
	LastError       string          `json:"last_error,omitempty"`
}

// HostsFileStatus represents the status of the hosts file
type HostsFileStatus struct {
	BackupExists   bool     `json:"backup_exists"`
	EntriesValid   bool     `json:"entries_valid"`
	MissingEntries []string `json:"missing_entries,omitempty"`
	ExtraEntries   []string `json:"extra_entries,omitempty"`
}

// ServiceConfig represents the configuration model
type ServiceConfig struct {
	Ports        []int     `json:"ports"`
	LastModified time.Time `json:"last_modified"`
	ConfigPath   string    `json:"config_path"`
	HostsPath    string    `json:"hosts_path"`
	BackupPath   string    `json:"backup_path"`
}

// ErrorType represents different types of service errors
type ErrorType int

const (
	ConfigError ErrorType = iota
	NetworkError
	SystemError
	RuntimeError
)

// ServiceError represents a service error with context
type ServiceError struct {
	Type        ErrorType
	Message     string
	Underlying  error
	Timestamp   time.Time
	Recoverable bool
}

// StructuredLogger provides structured logging capabilities
type StructuredLogger struct {
	logger *log.Logger
}

// NewStructuredLogger creates a new structured logger
func NewStructuredLogger(logger *log.Logger) *StructuredLogger {
	return &StructuredLogger{logger: logger}
}

// LogRedirect logs a redirect operation with structured information
func (sl *StructuredLogger) LogRedirect(sourceHost, targetURL, clientIP string, statusCode int) {
	sl.logger.Printf("[REDIRECT] source=%s target=%s client=%s status=%d",
		sourceHost, targetURL, clientIP, statusCode)
}

// LogError logs an error with structured information
func (sl *StructuredLogger) LogError(operation, message string, err error) {
	if err != nil {
		sl.logger.Printf("[ERROR] operation=%s message=%s error=%v", operation, message, err)
	} else {
		sl.logger.Printf("[ERROR] operation=%s message=%s", operation, message)
	}
}

// LogInfo logs informational messages with structured format
func (sl *StructuredLogger) LogInfo(operation, message string) {
	sl.logger.Printf("[INFO] operation=%s message=%s", operation, message)
}

// LogWarning logs warning messages with structured format
func (sl *StructuredLogger) LogWarning(operation, message string) {
	sl.logger.Printf("[WARN] operation=%s message=%s", operation, message)
}

// LogStartup logs service startup information
func (sl *StructuredLogger) LogStartup(version, configPath string, portCount int) {
	sl.logger.Printf("[STARTUP] service=port-redirect-service version=%s config=%s ports=%d",
		version, configPath, portCount)
}

// LogShutdown logs service shutdown information
func (sl *StructuredLogger) LogShutdown(reason string, uptime time.Duration) {
	sl.logger.Printf("[SHUTDOWN] reason=%s uptime=%s", reason, uptime.String())
}

// LogConfigChange logs configuration changes
func (sl *StructuredLogger) LogConfigChange(oldPortCount, newPortCount int) {
	sl.logger.Printf("[CONFIG] operation=reload old_ports=%d new_ports=%d", oldPortCount, newPortCount)
}

// LogFileManager handles log file rotation and size management
type LogFileManager struct {
	logFilePath string
	maxSize     int64 // Maximum size in bytes
	maxFiles    int   // Maximum number of rotated files to keep
	logger      *log.Logger
}

// NewLogFileManager creates a new log file manager
func NewLogFileManager(logFilePath string, maxSizeMB int, maxFiles int) *LogFileManager {
	return &LogFileManager{
		logFilePath: logFilePath,
		maxSize:     int64(maxSizeMB) * 1024 * 1024, // Convert MB to bytes
		maxFiles:    maxFiles,
	}
}

// SetupLogFile sets up logging to a file with rotation
func (lfm *LogFileManager) SetupLogFile() (*log.Logger, error) {
	// Create log directory if it doesn't exist
	logDir := filepath.Dir(lfm.logFilePath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file for appending
	logFile, err := os.OpenFile(lfm.logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Create logger that writes to both file and stdout
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger := log.New(multiWriter, "[PORT-REDIRECT] ", log.LstdFlags)

	lfm.logger = logger
	return logger, nil
}

// CheckRotation checks if log rotation is needed and performs it
func (lfm *LogFileManager) CheckRotation() error {
	// Check if log file exists and get its size
	fileInfo, err := os.Stat(lfm.logFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, no rotation needed
		}
		return fmt.Errorf("failed to stat log file: %w", err)
	}

	// Check if rotation is needed
	if fileInfo.Size() < lfm.maxSize {
		return nil // File is not large enough for rotation
	}

	// Perform rotation
	return lfm.rotateLogFile()
}

// rotateLogFile performs the actual log file rotation
func (lfm *LogFileManager) rotateLogFile() error {
	// Close current log file if logger exists
	if lfm.logger != nil {
		lfm.logger.Println("Rotating log file...")
	}

	// Rotate existing files
	for i := lfm.maxFiles - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", lfm.logFilePath, i)
		newPath := fmt.Sprintf("%s.%d", lfm.logFilePath, i+1)

		if _, err := os.Stat(oldPath); err == nil {
			if i == lfm.maxFiles-1 {
				// Remove the oldest file
				os.Remove(newPath)
			}
			os.Rename(oldPath, newPath)
		}
	}

	// Move current log file to .1
	rotatedPath := fmt.Sprintf("%s.1", lfm.logFilePath)
	if err := os.Rename(lfm.logFilePath, rotatedPath); err != nil {
		return fmt.Errorf("failed to rotate log file: %w", err)
	}

	// Create new log file
	newLogger, err := lfm.SetupLogFile()
	if err != nil {
		return fmt.Errorf("failed to create new log file after rotation: %w", err)
	}

	lfm.logger = newLogger
	lfm.logger.Println("Log file rotated successfully")

	return nil
}

// Default configuration values
const (
	DefaultConfigPath   = "/etc/port-redirect/config.txt"
	DefaultHostsPath    = "/etc/hosts"
	DefaultBackupPath   = "/etc/port-redirect/hosts.backup"
	DefaultPorts        = "3000\n8080\n5173"
	ConfigWatchInterval = 2 * time.Second
)

// Regex pattern to match <port>.<tld> format in Host header
// Supports common development TLDs: .local, .dev, .test, .localhost
var portExtractionRegex = regexp.MustCompile(`^(\d+)\.(local|dev|test|localhost|ai|com|net|org)$`)

// ConfigWatcher watches for configuration file changes
type ConfigWatcher struct {
	configPath  string
	lastModTime time.Time
	stopChan    chan struct{}
	reloadChan  chan []int
	errorChan   chan error
	logger      *log.Logger
}

// parseConfigFile reads and parses the configuration file
func parseConfigFile(configPath string) ([]int, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var ports []int
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse port number
		port, err := strconv.Atoi(line)
		if err != nil {
			return nil, fmt.Errorf("invalid port number '%s' on line %d: %w", line, lineNum, err)
		}

		// Validate port range
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port number %d on line %d is out of valid range (1-65535)", port, lineNum)
		}

		ports = append(ports, port)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	return ports, nil
}

// createDefaultConfig creates a default configuration file if it doesn't exist
func createDefaultConfig(configPath string) error {
	// Check if config file already exists
	if _, err := os.Stat(configPath); err == nil {
		return nil // File already exists, nothing to do
	}

	// Create directory if it doesn't exist
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create default config content
	defaultContent := fmt.Sprintf(`# Port Redirect Service Configuration
# One port per line, comments start with #
# Common development ports:

%s
`, DefaultPorts)

	// Write default config file
	if err := os.WriteFile(configPath, []byte(defaultContent), 0644); err != nil {
		return fmt.Errorf("failed to create default config file: %w", err)
	}

	return nil
}

// loadConfig loads configuration from file, creating default if needed
func loadConfig(configPath string) ([]int, error) {
	// Try to create default config if it doesn't exist
	if err := createDefaultConfig(configPath); err != nil {
		return nil, fmt.Errorf("failed to create default config: %w", err)
	}

	// Parse the configuration file
	ports, err := parseConfigFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports found in configuration file")
	}

	return ports, nil
}

// NewConfigWatcher creates a new configuration file watcher
func NewConfigWatcher(configPath string, logger *log.Logger) *ConfigWatcher {
	return &ConfigWatcher{
		configPath: configPath,
		stopChan:   make(chan struct{}),
		reloadChan: make(chan []int, 1),
		errorChan:  make(chan error, 1),
		logger:     logger,
	}
}

// Start begins watching the configuration file for changes
func (cw *ConfigWatcher) Start() error {
	// Get initial modification time
	fileInfo, err := os.Stat(cw.configPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}
	cw.lastModTime = fileInfo.ModTime()

	// Start watching in a goroutine
	go cw.watchLoop()

	cw.logger.Printf("Started watching config file: %s", cw.configPath)
	return nil
}

// Stop stops the configuration file watcher
func (cw *ConfigWatcher) Stop() {
	select {
	case <-cw.stopChan:
		// Already stopped
		return
	default:
		close(cw.stopChan)
		cw.logger.Println("Stopped config file watcher")
	}
}

// ReloadChan returns the channel that receives new configurations
func (cw *ConfigWatcher) ReloadChan() <-chan []int {
	return cw.reloadChan
}

// ErrorChan returns the channel that receives watcher errors
func (cw *ConfigWatcher) ErrorChan() <-chan error {
	return cw.errorChan
}

// watchLoop is the main watching loop that runs in a goroutine
func (cw *ConfigWatcher) watchLoop() {
	ticker := time.NewTicker(ConfigWatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cw.stopChan:
			return
		case <-ticker.C:
			if err := cw.checkForChanges(); err != nil {
				select {
				case cw.errorChan <- err:
				default:
					// Channel is full, log the error
					cw.logger.Printf("Config watcher error (channel full): %v", err)
				}
			}
		}
	}
}

// checkForChanges checks if the configuration file has been modified
func (cw *ConfigWatcher) checkForChanges() error {
	fileInfo, err := os.Stat(cw.configPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}

	modTime := fileInfo.ModTime()
	if modTime.After(cw.lastModTime) {
		cw.lastModTime = modTime
		cw.logger.Println("Config file changed, reloading...")

		// Try to load the new configuration
		newPorts, err := parseConfigFile(cw.configPath)
		if err != nil {
			return fmt.Errorf("failed to reload config: %w", err)
		}

		// Send the new configuration
		select {
		case cw.reloadChan <- newPorts:
			cw.logger.Printf("Config reloaded successfully with %d ports", len(newPorts))
		default:
			// Channel is full, this shouldn't happen in normal operation
			cw.logger.Println("Warning: config reload channel is full")
		}
	}

	return nil
}

// validateConfigUpdate validates a configuration update before applying it
func validateConfigUpdate(newPorts []int) error {
	if len(newPorts) == 0 {
		return fmt.Errorf("configuration must contain at least one port")
	}

	// Check for duplicate ports
	portMap := make(map[int]bool)
	for _, port := range newPorts {
		if portMap[port] {
			return fmt.Errorf("duplicate port found: %d", port)
		}
		portMap[port] = true
	}

	return nil
}

// extractPortFromHost extracts port number from Host header using regex pattern
// Returns the port number and true if extraction is successful, 0 and false otherwise
func extractPortFromHost(host string) (int, bool) {
	// Remove any port suffix from host (e.g., "3000.local:8080" -> "3000.local")
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// Match against the regex pattern
	matches := portExtractionRegex.FindStringSubmatch(host)
	if len(matches) != 3 {
		return 0, false
	}

	// Extract port number from the first capture group
	portStr := matches[1]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, false
	}

	return port, true
}

// validatePort checks if the port number is within valid range (1-65535)
func validatePort(port int) bool {
	return port >= 1 && port <= 65535
}

// isPortConfigured checks if the extracted port is in the configured ports list
func isPortConfigured(port int, configuredPorts []int) bool {
	for _, configuredPort := range configuredPorts {
		if configuredPort == port {
			return true
		}
	}
	return false
}

// handleRedirect handles HTTP requests and performs port-based redirects
func (s *PortRedirectService) handleRedirect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	clientIP := s.getClientIP(r)

	// Log the incoming request
	s.structuredLogger.LogInfo("request_received", fmt.Sprintf("host=%s client=%s", host, clientIP))

	// Extract port from host header
	port, extracted := extractPortFromHost(host)
	if !extracted {
		// Host doesn't match expected format, return 404
		s.structuredLogger.LogError("port_extraction", fmt.Sprintf("Invalid host format: %s", host), nil)
		http.Error(w, "Not Found: Host format should be <port>.<tld> (e.g., 3000.local)", http.StatusNotFound)
		s.structuredLogger.LogRedirect(host, "none", clientIP, http.StatusNotFound)
		return
	}

	// Validate port number
	if !validatePort(port) {
		// Port is out of valid range, return 400
		s.structuredLogger.LogError("port_validation", fmt.Sprintf("Invalid port number: %d", port), nil)
		http.Error(w, fmt.Sprintf("Bad Request: Port number %d is out of valid range (1-65535)", port), http.StatusBadRequest)
		s.structuredLogger.LogRedirect(host, "none", clientIP, http.StatusBadRequest)
		return
	}

	// Check if port is configured
	if !isPortConfigured(port, s.config.Ports) {
		// Port is not in configuration, return 404
		s.structuredLogger.LogWarning("port_not_configured", fmt.Sprintf("Port %d not in configuration", port))
		http.Error(w, fmt.Sprintf("Not Found: Port %d is not configured in the service", port), http.StatusNotFound)
		s.structuredLogger.LogRedirect(host, "none", clientIP, http.StatusNotFound)
		return
	}

	// Generate redirect URL
	redirectURL := fmt.Sprintf("http://localhost:%d", port)

	// Log the successful redirect
	s.structuredLogger.LogRedirect(host, redirectURL, clientIP, http.StatusMovedPermanently)

	// Send HTTP 301 permanent redirect
	http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
}

// getClientIP extracts the client IP address from the request
func (s *PortRedirectService) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxied requests)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}

	return r.RemoteAddr
}

// handleStatus handles requests to the /status endpoint
func (s *PortRedirectService) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Check if JSON format is requested
	if r.URL.Query().Get("format") == "json" || r.Header.Get("Accept") == "application/json" {
		s.handleStatusJSON(w, r)
		return
	}

	// Generate HTML status page
	s.handleStatusHTML(w, r)
}

// handleStatusJSON handles JSON API requests for status
func (s *PortRedirectService) handleStatusJSON(w http.ResponseWriter, r *http.Request) {
	status := s.GetServiceStatus()
	config := s.GetServiceConfig()
	configErrors := s.ValidateConfiguration()

	response := map[string]interface{}{
		"status":        status,
		"config":        config,
		"config_errors": configErrors,
		"timestamp":     time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Simple JSON encoding without external dependencies
	s.writeJSON(w, response)
}

// handleStatusHTML generates and serves the HTML status page
func (s *PortRedirectService) handleStatusHTML(w http.ResponseWriter, r *http.Request) {
	status := s.GetServiceStatus()
	config := s.GetServiceConfig()
	configErrors := s.ValidateConfiguration()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	html := s.generateStatusHTML(status, config, configErrors)
	fmt.Fprint(w, html)
}

// generateStatusHTML creates the HTML content for the status page
func (s *PortRedirectService) generateStatusHTML(status *ServiceStatus, config *ServiceConfig, configErrors []string) string {
	// Format uptime
	uptimeStr := s.formatDuration(status.Uptime)

	// Format timestamps
	configLoadedStr := status.ConfigLoaded.Format("2006-01-02 15:04:05")
	lastModifiedStr := config.LastModified.Format("2006-01-02 15:04:05")

	// Build ports list
	portsStr := ""
	for i, port := range status.PortsConfigured {
		if i > 0 {
			portsStr += ", "
		}
		portsStr += fmt.Sprintf("%d", port)
	}

	// Build hosts status
	hostsStatusClass := "status-ok"
	hostsStatusText := "Valid"
	if !status.HostsStatus.EntriesValid {
		hostsStatusClass = "status-error"
		hostsStatusText = "Invalid"
	}

	// Build missing entries
	missingEntriesHTML := ""
	if len(status.HostsStatus.MissingEntries) > 0 {
		missingEntriesHTML = "<h4>Missing Entries:</h4><ul>"
		for _, entry := range status.HostsStatus.MissingEntries {
			missingEntriesHTML += fmt.Sprintf("<li>%s</li>", entry)
		}
		missingEntriesHTML += "</ul>"
	}

	// Build extra entries
	extraEntriesHTML := ""
	if len(status.HostsStatus.ExtraEntries) > 0 {
		extraEntriesHTML = "<h4>Extra Entries:</h4><ul>"
		for _, entry := range status.HostsStatus.ExtraEntries {
			extraEntriesHTML += fmt.Sprintf("<li>%s</li>", entry)
		}
		extraEntriesHTML += "</ul>"
	}

	// Build configuration errors
	configErrorsHTML := ""
	if len(configErrors) > 0 {
		configErrorsHTML = "<div class='section error'><h3>Configuration Errors</h3><ul>"
		for _, err := range configErrors {
			configErrorsHTML += fmt.Sprintf("<li>%s</li>", err)
		}
		configErrorsHTML += "</ul></div>"
	}

	// Build last error
	lastErrorHTML := ""
	if status.LastError != "" {
		lastErrorHTML = fmt.Sprintf(`
		<div class="section error">
			<h3>Last Error</h3>
			<p>%s</p>
		</div>`, status.LastError)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Redirect Service - Status</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #007acc;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
        }
        h3 {
            color: #666;
            margin-top: 20px;
        }
        .section {
            margin: 20px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #007acc;
            background-color: #f8f9fa;
        }
        .section.error {
            border-left-color: #dc3545;
            background-color: #f8d7da;
        }
        .status-ok {
            color: #28a745;
            font-weight: bold;
        }
        .status-error {
            color: #dc3545;
            font-weight: bold;
        }
        .info-grid {
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 10px;
            margin: 10px 0;
        }
        .info-label {
            font-weight: bold;
            color: #666;
        }
        .ports {
            font-family: monospace;
            background-color: #e9ecef;
            padding: 5px 10px;
            border-radius: 3px;
        }
        .refresh-link {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background-color: #007acc;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
        .refresh-link:hover {
            background-color: #005a9e;
        }
        .json-link {
            display: inline-block;
            margin-left: 10px;
            padding: 10px 20px;
            background-color: #6c757d;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
        .json-link:hover {
            background-color: #545b62;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Port Redirect Service Status</h1>
        
        <div class="section">
            <h2>Service Information</h2>
            <div class="info-grid">
                <div class="info-label">Uptime:</div>
                <div>%s</div>
                <div class="info-label">Config Loaded:</div>
                <div>%s</div>
                <div class="info-label">Configured Ports:</div>
                <div class="ports">%s</div>
            </div>
        </div>

        <div class="section">
            <h2>Hosts File Status</h2>
            <div class="info-grid">
                <div class="info-label">Backup Exists:</div>
                <div class="%s">%t</div>
                <div class="info-label">Entries Valid:</div>
                <div class="%s">%s</div>
            </div>
            %s
            %s
        </div>

        <div class="section">
            <h2>Configuration</h2>
            <div class="info-grid">
                <div class="info-label">Config File:</div>
                <div>%s</div>
                <div class="info-label">Last Modified:</div>
                <div>%s</div>
                <div class="info-label">Hosts File:</div>
                <div>%s</div>
                <div class="info-label">Backup Path:</div>
                <div>%s</div>
            </div>
        </div>

        %s
        %s

        <div style="margin-top: 30px;">
            <a href="/status" class="refresh-link">Refresh</a>
            <a href="/status?format=json" class="json-link">JSON API</a>
        </div>
    </div>
</body>
</html>`,
		uptimeStr,
		configLoadedStr,
		portsStr,
		s.getBoolStatusClass(status.HostsStatus.BackupExists),
		status.HostsStatus.BackupExists,
		hostsStatusClass,
		hostsStatusText,
		missingEntriesHTML,
		extraEntriesHTML,
		config.ConfigPath,
		lastModifiedStr,
		config.HostsPath,
		config.BackupPath,
		configErrorsHTML,
		lastErrorHTML,
	)
}

// formatDuration formats a duration into a human-readable string
func (s *PortRedirectService) formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1f seconds", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1f minutes", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	return fmt.Sprintf("%.1f days", d.Hours()/24)
}

// getBoolStatusClass returns the appropriate CSS class for boolean status
func (s *PortRedirectService) getBoolStatusClass(value bool) string {
	if value {
		return "status-ok"
	}
	return "status-error"
}

// writeJSON writes a simple JSON response without external dependencies
func (s *PortRedirectService) writeJSON(w http.ResponseWriter, data map[string]interface{}) {
	// Simple JSON serialization for basic types
	fmt.Fprint(w, "{\n")

	first := true
	for key, value := range data {
		if !first {
			fmt.Fprint(w, ",\n")
		}
		first = false

		fmt.Fprintf(w, "  \"%s\": ", key)
		s.writeJSONValue(w, value)
	}

	fmt.Fprint(w, "\n}")
}

// writeJSONValue writes a JSON value without external dependencies
func (s *PortRedirectService) writeJSONValue(w http.ResponseWriter, value interface{}) {
	switch v := value.(type) {
	case string:
		fmt.Fprintf(w, "\"%s\"", strings.ReplaceAll(v, "\"", "\\\""))
	case int:
		fmt.Fprintf(w, "%d", v)
	case bool:
		fmt.Fprintf(w, "%t", v)
	case time.Time:
		fmt.Fprintf(w, "\"%s\"", v.Format(time.RFC3339))
	case time.Duration:
		fmt.Fprintf(w, "\"%s\"", v.String())
	case []int:
		fmt.Fprint(w, "[")
		for i, item := range v {
			if i > 0 {
				fmt.Fprint(w, ", ")
			}
			fmt.Fprintf(w, "%d", item)
		}
		fmt.Fprint(w, "]")
	case []string:
		fmt.Fprint(w, "[")
		for i, item := range v {
			if i > 0 {
				fmt.Fprint(w, ", ")
			}
			fmt.Fprintf(w, "\"%s\"", strings.ReplaceAll(item, "\"", "\\\""))
		}
		fmt.Fprint(w, "]")
	case *ServiceStatus:
		fmt.Fprint(w, "{\n")
		fmt.Fprintf(w, "    \"uptime\": \"%s\",\n", v.Uptime.String())
		fmt.Fprintf(w, "    \"config_loaded\": \"%s\",\n", v.ConfigLoaded.Format(time.RFC3339))
		fmt.Fprint(w, "    \"ports_configured\": [")
		for i, port := range v.PortsConfigured {
			if i > 0 {
				fmt.Fprint(w, ", ")
			}
			fmt.Fprintf(w, "%d", port)
		}
		fmt.Fprint(w, "],\n")
		fmt.Fprint(w, "    \"hosts_status\": {\n")
		fmt.Fprintf(w, "      \"backup_exists\": %t,\n", v.HostsStatus.BackupExists)
		fmt.Fprintf(w, "      \"entries_valid\": %t", v.HostsStatus.EntriesValid)
		if len(v.HostsStatus.MissingEntries) > 0 {
			fmt.Fprint(w, ",\n      \"missing_entries\": [")
			for i, entry := range v.HostsStatus.MissingEntries {
				if i > 0 {
					fmt.Fprint(w, ", ")
				}
				fmt.Fprintf(w, "\"%s\"", strings.ReplaceAll(entry, "\"", "\\\""))
			}
			fmt.Fprint(w, "]")
		}
		if len(v.HostsStatus.ExtraEntries) > 0 {
			fmt.Fprint(w, ",\n      \"extra_entries\": [")
			for i, entry := range v.HostsStatus.ExtraEntries {
				if i > 0 {
					fmt.Fprint(w, ", ")
				}
				fmt.Fprintf(w, "\"%s\"", strings.ReplaceAll(entry, "\"", "\\\""))
			}
			fmt.Fprint(w, "]")
		}
		fmt.Fprint(w, "\n    }")
		if v.LastError != "" {
			fmt.Fprintf(w, ",\n    \"last_error\": \"%s\"", strings.ReplaceAll(v.LastError, "\"", "\\\""))
		}
		fmt.Fprint(w, "\n  }")
	case *ServiceConfig:
		fmt.Fprint(w, "{\n")
		fmt.Fprint(w, "    \"ports\": [")
		for i, port := range v.Ports {
			if i > 0 {
				fmt.Fprint(w, ", ")
			}
			fmt.Fprintf(w, "%d", port)
		}
		fmt.Fprint(w, "],\n")
		fmt.Fprintf(w, "    \"last_modified\": \"%s\",\n", v.LastModified.Format(time.RFC3339))
		fmt.Fprintf(w, "    \"config_path\": \"%s\",\n", v.ConfigPath)
		fmt.Fprintf(w, "    \"hosts_path\": \"%s\",\n", v.HostsPath)
		fmt.Fprintf(w, "    \"backup_path\": \"%s\"\n", v.BackupPath)
		fmt.Fprint(w, "  }")
	default:
		fmt.Fprintf(w, "null")
	}
}

// GetServiceStatus collects and returns the current service status
func (s *PortRedirectService) GetServiceStatus() *ServiceStatus {
	// Calculate uptime
	uptime := time.Since(s.startTime)

	// Check hosts file validity
	hostsStatus := s.getHostsFileStatus()

	return &ServiceStatus{
		Uptime:          uptime,
		ConfigLoaded:    s.configLoaded,
		PortsConfigured: s.config.Ports,
		HostsStatus:     hostsStatus,
		LastError:       s.lastError,
	}
}

// getHostsFileStatus checks the current status of the hosts file
func (s *PortRedirectService) getHostsFileStatus() HostsFileStatus {
	// Check if backup exists
	backupExists := s.hostsManager.BackupExists()

	// Validate hosts file entries
	entriesValid, missingEntries, extraEntries := s.hostsManager.ValidateEntries(s.config.Ports)

	return HostsFileStatus{
		BackupExists:   backupExists,
		EntriesValid:   entriesValid,
		MissingEntries: missingEntries,
		ExtraEntries:   extraEntries,
	}
}

// ValidateConfiguration validates the current configuration
func (s *PortRedirectService) ValidateConfiguration() []string {
	var errors []string

	// Check if configuration file exists
	if _, err := os.Stat(s.config.ConfigFilePath); os.IsNotExist(err) {
		errors = append(errors, fmt.Sprintf("Configuration file does not exist: %s", s.config.ConfigFilePath))
	}

	// Check if ports are valid
	if len(s.config.Ports) == 0 {
		errors = append(errors, "No ports configured")
	}

	for _, port := range s.config.Ports {
		if !validatePort(port) {
			errors = append(errors, fmt.Sprintf("Invalid port number: %d (must be 1-65535)", port))
		}
	}

	// Check for duplicate ports
	portMap := make(map[int]bool)
	for _, port := range s.config.Ports {
		if portMap[port] {
			errors = append(errors, fmt.Sprintf("Duplicate port found: %d", port))
		}
		portMap[port] = true
	}

	return errors
}

// UpdateConfigLoaded updates the configuration loaded timestamp
func (s *PortRedirectService) UpdateConfigLoaded() {
	s.configLoaded = time.Now()
}

// SetLastError sets the last error message
func (s *PortRedirectService) SetLastError(err string) {
	s.lastError = err
}

// ClearLastError clears the last error message
func (s *PortRedirectService) ClearLastError() {
	s.lastError = ""
}

// GetServiceConfig returns the current service configuration
func (s *PortRedirectService) GetServiceConfig() *ServiceConfig {
	// Get config file modification time
	var lastModified time.Time
	if fileInfo, err := os.Stat(s.config.ConfigFilePath); err == nil {
		lastModified = fileInfo.ModTime()
	}

	return &ServiceConfig{
		Ports:        s.config.Ports,
		LastModified: lastModified,
		ConfigPath:   s.config.ConfigFilePath,
		HostsPath:    DefaultHostsPath,
		BackupPath:   s.config.HostsBackupPath,
	}
}

// setupRoutes configures the HTTP server routes
func (s *PortRedirectService) setupRoutes() {
	mux := http.NewServeMux()

	// Status endpoint
	mux.HandleFunc("/status", s.handleStatus)

	// Default handler for all other requests (redirect handler)
	mux.HandleFunc("/", s.handleRedirect)

	s.server.Handler = mux
}

// Start starts the HTTP server and begins listening for requests
func (s *PortRedirectService) Start() error {
	s.structuredLogger.LogInfo("server_start", "Starting HTTP server on port 80")

	// Check log rotation before starting
	if s.logFileManager != nil {
		if err := s.logFileManager.CheckRotation(); err != nil {
			s.structuredLogger.LogWarning("log_rotation", fmt.Sprintf("Failed to check log rotation: %v", err))
		}
	}

	// Start the server in a goroutine so it doesn't block
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.structuredLogger.LogError("server_error", "HTTP server encountered an error", err)
			s.lastError = fmt.Sprintf("HTTP server error: %v", err)
		}
	}()

	s.structuredLogger.LogInfo("server_started", "HTTP server started successfully on port 80")
	return nil
}

// Stop gracefully shuts down the HTTP server
func (s *PortRedirectService) Stop(ctx context.Context) error {
	uptime := time.Since(s.startTime)
	s.structuredLogger.LogShutdown("graceful_shutdown", uptime)

	// Stop config watcher first to prevent new configuration changes during shutdown
	if s.configWatcher != nil {
		s.configWatcher.Stop()
		s.structuredLogger.LogInfo("shutdown_config_watcher", "Stopped configuration watcher")
		s.configWatcher = nil // Prevent double-stop
	}

	// Gracefully shutdown the HTTP server
	if err := s.server.Shutdown(ctx); err != nil {
		s.structuredLogger.LogError("server_shutdown", "Error during server shutdown", err)
		// If graceful shutdown fails, force close
		if closeErr := s.server.Close(); closeErr != nil {
			s.structuredLogger.LogError("server_force_close", "Error during forced server close", closeErr)
		}
		return err
	}

	s.structuredLogger.LogInfo("server_stopped", "HTTP server stopped successfully")
	return nil
}

// Cleanup performs cleanup operations including hosts file restoration
func (s *PortRedirectService) Cleanup() error {
	s.structuredLogger.LogInfo("cleanup_start", "Performing cleanup operations")

	var cleanupErrors []error

	// Stop config watcher if it exists (may already be stopped in Stop method)
	if s.configWatcher != nil {
		s.configWatcher.Stop()
		s.structuredLogger.LogInfo("cleanup_config_watcher", "Stopped configuration watcher")
		s.configWatcher = nil // Prevent double-stop
	}

	// Remove hosts file entries
	if err := s.hostsManager.RemovePortEntries(); err != nil {
		s.structuredLogger.LogError("cleanup_hosts", "Failed to remove hosts file entries", err)
		cleanupErrors = append(cleanupErrors, fmt.Errorf("hosts cleanup failed: %w", err))

		// Try to restore from backup as fallback
		s.structuredLogger.LogInfo("cleanup_fallback", "Attempting to restore hosts file from backup")
		if restoreErr := s.hostsManager.RestoreBackup(); restoreErr != nil {
			s.structuredLogger.LogError("cleanup_restore", "Failed to restore hosts file from backup", restoreErr)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("backup restore failed: %w", restoreErr))
		} else {
			s.structuredLogger.LogInfo("cleanup_restore_success", "Successfully restored hosts file from backup")
		}
	} else {
		s.structuredLogger.LogInfo("cleanup_hosts_success", "Successfully removed hosts file entries")
	}

	// Log rotation cleanup if needed
	if s.logFileManager != nil {
		if err := s.logFileManager.CheckRotation(); err != nil {
			s.structuredLogger.LogWarning("cleanup_log_rotation", fmt.Sprintf("Final log rotation check failed: %v", err))
		}
	}

	if len(cleanupErrors) > 0 {
		// Combine all cleanup errors
		var errorMessages []string
		for _, err := range cleanupErrors {
			errorMessages = append(errorMessages, err.Error())
		}
		combinedError := fmt.Errorf("cleanup completed with errors: %s", strings.Join(errorMessages, "; "))
		s.structuredLogger.LogError("cleanup_partial", "Cleanup completed with some errors", combinedError)
		return combinedError
	}

	s.structuredLogger.LogInfo("cleanup_completed", "Cleanup operations completed successfully")
	return nil
}

// handleConfigReloads handles configuration file changes
func (s *PortRedirectService) handleConfigReloads() {
	for {
		select {
		case newPorts := <-s.configWatcher.ReloadChan():
			oldPortCount := len(s.config.Ports)
			s.structuredLogger.LogConfigChange(oldPortCount, len(newPorts))

			// Validate the new configuration
			if err := validateConfigUpdate(newPorts); err != nil {
				s.structuredLogger.LogError("config_validation", "Invalid configuration update", err)
				s.lastError = fmt.Sprintf("Invalid configuration update: %v", err)
				continue
			}

			// Update the service configuration
			s.config.Ports = newPorts
			s.configLoaded = time.Now()

			// Update hosts file entries
			if err := s.hostsManager.UpdatePortEntries(newPorts); err != nil {
				s.structuredLogger.LogError("config_hosts_update", "Failed to update hosts file entries", err)
				s.lastError = fmt.Sprintf("Failed to update hosts file entries: %v", err)
			} else {
				s.structuredLogger.LogInfo("config_hosts_updated", fmt.Sprintf("Successfully updated hosts file entries for %d ports", len(newPorts)))
				s.lastError = "" // Clear any previous error
			}

		case err := <-s.configWatcher.ErrorChan():
			s.structuredLogger.LogError("config_watcher", "Configuration watcher error", err)
			s.lastError = fmt.Sprintf("Configuration watcher error: %v", err)
		}
	}
}

// checkPrivileges checks if the service has the required privileges to run
func checkPrivileges() error {
	// Check if we can bind to port 80 (requires root/admin privileges on Unix systems)
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "access is denied") {
			return fmt.Errorf("insufficient privileges: binding to port 80 requires root/administrator privileges. Please run with sudo (Linux/macOS) or as Administrator (Windows)")
		}
		// Port might be in use by another service
		return fmt.Errorf("cannot bind to port 80: %v. This may indicate another instance is running or another service is using port 80", err)
	}
	listener.Close()

	// Check if we can write to /etc/hosts (Unix systems)
	if _, err := os.Stat("/etc/hosts"); err == nil {
		// Try to open hosts file for writing to test permissions
		file, err := os.OpenFile("/etc/hosts", os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			if os.IsPermission(err) {
				return fmt.Errorf("insufficient privileges: modifying /etc/hosts requires root/administrator privileges. Please run with sudo (Linux/macOS) or as Administrator (Windows)")
			}
			return fmt.Errorf("cannot access /etc/hosts: %v", err)
		}
		file.Close()
	}

	return nil
}

// checkSingleInstance checks if another instance of the service is already running
func checkSingleInstance() error {
	// Try to bind to port 80 temporarily to check if it's available
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("port 80 is already in use (service may already be running)")
	}
	listener.Close()
	return nil
}

// NewPortRedirectService creates a new instance of the port redirect service
func NewPortRedirectService(config *Config, logger *log.Logger, logFileManager *LogFileManager) *PortRedirectService {
	now := time.Now()
	service := &PortRedirectService{
		config:           config,
		logger:           logger,
		structuredLogger: NewStructuredLogger(logger),
		logFileManager:   logFileManager,
		hostsManager:     NewHostsManager(DefaultHostsPath, config.HostsBackupPath),
		server: &http.Server{
			Addr: ":80",
		},
		startTime:    now,
		configLoaded: now,
	}

	// Setup HTTP routes
	service.setupRoutes()

	return service
}

func main() {
	// Setup log file management
	logFilePath := "/var/log/port-redirect.log"
	if os.Getenv("HOME") != "" {
		// Use user's home directory on macOS
		logFilePath = filepath.Join(os.Getenv("HOME"), "Library", "Logs", "port-redirect.log")
	}

	logFileManager := NewLogFileManager(logFilePath, 10, 5) // 10MB max size, keep 5 files
	logger, err := logFileManager.SetupLogFile()
	if err != nil {
		// Fall back to stdout only if log file setup fails
		logger = log.New(os.Stdout, "[PORT-REDIRECT] ", log.LstdFlags)
		logger.Printf("Warning: Failed to setup log file, using stdout only: %v", err)
	}

	structuredLogger := NewStructuredLogger(logger)
	structuredLogger.LogStartup("1.0.0", DefaultConfigPath, 0) // Port count will be updated after config load

	// Check if we have the required privileges
	if err := checkPrivileges(); err != nil {
		structuredLogger.LogError("startup", "Insufficient privileges", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Check if another instance is already running
	if err := checkSingleInstance(); err != nil {
		structuredLogger.LogError("startup", "Service is already running", err)
		os.Exit(0)
	}

	// Load configuration
	ports, err := loadConfig(DefaultConfigPath)
	if err != nil {
		structuredLogger.LogError("startup", "Failed to load configuration", err)
		os.Exit(1)
	}

	// Create service configuration
	config := &Config{
		Ports:           ports,
		ConfigFilePath:  DefaultConfigPath,
		HostsBackupPath: DefaultBackupPath,
		LogLevel:        "INFO",
	}

	// Log the actual port count now that we have it
	structuredLogger.LogStartup("1.0.0", DefaultConfigPath, len(ports))

	// Create service instance
	service := NewPortRedirectService(config, logger, logFileManager)

	// Create backup of hosts file
	if err := service.hostsManager.CreateBackup(); err != nil {
		service.structuredLogger.LogWarning("hosts_backup", fmt.Sprintf("Failed to create hosts file backup: %v", err))
	} else {
		service.structuredLogger.LogInfo("hosts_backup", "Created hosts file backup successfully")
	}

	// Setup hosts file entries for configured ports
	if err := service.hostsManager.AddPortEntries(config.Ports); err != nil {
		service.structuredLogger.LogWarning("hosts_setup", fmt.Sprintf("Failed to setup hosts file entries: %v", err))
	} else {
		service.structuredLogger.LogInfo("hosts_setup", fmt.Sprintf("Added hosts file entries for %d ports", len(config.Ports)))
	}

	// Start configuration watcher
	service.configWatcher = NewConfigWatcher(config.ConfigFilePath, logger)
	if err := service.configWatcher.Start(); err != nil {
		service.structuredLogger.LogWarning("config_watcher", fmt.Sprintf("Failed to start config watcher: %v", err))
	} else {
		service.structuredLogger.LogInfo("config_watcher", "Started configuration file watcher")
		// Handle configuration reloads
		go service.handleConfigReloads()
	}

	service.structuredLogger.LogInfo("service_initialized", fmt.Sprintf("Service initialized with %d configured ports", len(config.Ports)))

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Setup cleanup on unexpected termination
	defer func() {
		if r := recover(); r != nil {
			service.structuredLogger.LogError("panic_recovery", fmt.Sprintf("Service panicked: %v", r), nil)
			if err := service.Cleanup(); err != nil {
				service.structuredLogger.LogError("panic_cleanup", "Failed to cleanup after panic", err)
			}
		}
	}()

	// Start periodic log rotation check
	if logFileManager != nil {
		go func() {
			ticker := time.NewTicker(1 * time.Hour) // Check every hour
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					if err := logFileManager.CheckRotation(); err != nil {
						service.structuredLogger.LogWarning("log_rotation", fmt.Sprintf("Log rotation check failed: %v", err))
					}
				case <-sigChan:
					return // Exit when shutdown signal is received
				}
			}
		}()
	}

	// Start the HTTP server
	if err := service.Start(); err != nil {
		service.structuredLogger.LogError("startup", "Failed to start HTTP server", err)
		os.Exit(1)
	}

	// Wait for shutdown signal
	sig := <-sigChan
	service.structuredLogger.LogInfo("shutdown_signal", fmt.Sprintf("Received signal %v, initiating graceful shutdown", sig))

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Track shutdown success
	shutdownSuccess := true

	// Stop the HTTP server
	if err := service.Stop(ctx); err != nil {
		service.structuredLogger.LogError("shutdown", "Error during server shutdown", err)
		shutdownSuccess = false
	}

	// Perform cleanup (always attempt cleanup even if server shutdown failed)
	if err := service.Cleanup(); err != nil {
		service.structuredLogger.LogError("cleanup", "Error during cleanup", err)
		shutdownSuccess = false
	}

	if shutdownSuccess {
		service.structuredLogger.LogInfo("shutdown_complete", "Port Redirect Service stopped gracefully")
	} else {
		service.structuredLogger.LogError("shutdown_complete", "Port Redirect Service stopped with errors", nil)
		os.Exit(1)
	}
}
