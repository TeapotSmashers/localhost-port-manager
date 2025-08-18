package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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
	server        *http.Server
	config        *Config
	hostsManager  *HostsManager
	logger        *log.Logger
	configWatcher *ConfigWatcher
	startTime     time.Time
	configLoaded  time.Time
	lastError     string
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
	close(cw.stopChan)
	cw.logger.Println("Stopped config file watcher")
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

	// Log the incoming request
	s.logger.Printf("Received request for host: %s", host)

	// Extract port from host header
	port, extracted := extractPortFromHost(host)
	if !extracted {
		// Host doesn't match expected format, return 404
		s.logger.Printf("Invalid host format: %s", host)
		http.Error(w, "Not Found: Host format should be <port>.<tld> (e.g., 3000.local)", http.StatusNotFound)
		return
	}

	// Validate port number
	if !validatePort(port) {
		// Port is out of valid range, return 400
		s.logger.Printf("Invalid port number: %d", port)
		http.Error(w, fmt.Sprintf("Bad Request: Port number %d is out of valid range (1-65535)", port), http.StatusBadRequest)
		return
	}

	// Check if port is configured
	if !isPortConfigured(port, s.config.Ports) {
		// Port is not in configuration, return 404
		s.logger.Printf("Port %d not configured", port)
		http.Error(w, fmt.Sprintf("Not Found: Port %d is not configured in the service", port), http.StatusNotFound)
		return
	}

	// Generate redirect URL
	redirectURL := fmt.Sprintf("http://localhost:%d", port)

	// Log the redirect
	s.logger.Printf("Redirecting %s -> %s", host, redirectURL)

	// Send HTTP 301 permanent redirect
	http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
}

// handleStatus handles requests to the /status endpoint
func (s *PortRedirectService) handleStatus(w http.ResponseWriter, r *http.Request) {
	// This will be implemented in a later task
	// For now, return a simple response
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Port Redirect Service Status\n")
	fmt.Fprintf(w, "Configured ports: %v\n", s.config.Ports)
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

// NewPortRedirectService creates a new instance of the port redirect service
func NewPortRedirectService(config *Config, logger *log.Logger) *PortRedirectService {
	now := time.Now()
	service := &PortRedirectService{
		config:       config,
		logger:       logger,
		hostsManager: NewHostsManager(DefaultHostsPath, config.HostsBackupPath),
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
	logger := log.New(os.Stdout, "[PORT-REDIRECT] ", log.LstdFlags)
	logger.Println("Port Redirect Service starting...")

	// Load configuration
	ports, err := loadConfig(DefaultConfigPath)
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	// Create service configuration
	config := &Config{
		Ports:           ports,
		ConfigFilePath:  DefaultConfigPath,
		HostsBackupPath: DefaultBackupPath,
		LogLevel:        "INFO",
	}

	// Create service instance
	service := NewPortRedirectService(config, logger)

	// Create backup of hosts file
	if err := service.hostsManager.CreateBackup(); err != nil {
		logger.Printf("Warning: Failed to create hosts file backup: %v", err)
	} else {
		logger.Println("Created hosts file backup")
	}

	logger.Printf("Service initialized with %d configured ports", len(config.Ports))
}
