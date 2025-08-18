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
	"sync"
	"syscall"
	"time"
)

// DeploymentMode represents the deployment mode of the service
type DeploymentMode int

const (
	LocalMode DeploymentMode = iota
	WebServiceMode
)

// String returns the string representation of the deployment mode
func (dm DeploymentMode) String() string {
	switch dm {
	case LocalMode:
		return "local"
	case WebServiceMode:
		return "web"
	default:
		return "unknown"
	}
}

// ParseDeploymentMode parses a string into a DeploymentMode
func ParseDeploymentMode(mode string) (DeploymentMode, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "local":
		return LocalMode, nil
	case "web", "webservice", "web-service":
		return WebServiceMode, nil
	default:
		return LocalMode, fmt.Errorf("invalid deployment mode: %s", mode)
	}
}

// WebServiceConfig holds web service specific configuration
type WebServiceConfig struct {
	Port           int      `json:"port"`
	DomainPatterns []string `json:"domain_patterns"`
	RateLimit      struct {
		Enabled bool `json:"enabled"`
		RPS     int  `json:"rps"`
		Burst   int  `json:"burst"`
	} `json:"rate_limit"`
}

// LocalModeConfig holds local mode specific configuration
type LocalModeConfig struct {
	HostsFilePath string `json:"hosts_file_path"`
	BackupPath    string `json:"backup_path"`
	ListenPort    int    `json:"listen_port"`
}

// DeploymentConfig holds deployment-specific configuration
type DeploymentConfig struct {
	Mode        DeploymentMode    `json:"mode"`
	LocalConfig *LocalModeConfig  `json:"local_config,omitempty"`
	WebConfig   *WebServiceConfig `json:"web_config,omitempty"`
}

// Config holds the service configuration
type Config struct {
	Ports            []int
	ConfigFilePath   string
	HostsBackupPath  string
	LogLevel         string
	DeploymentMode   DeploymentMode
	WebServicePort   int
	DomainPatterns   []string
	EnableRateLimit  bool
	RateLimitRPS     int
	DeploymentConfig *DeploymentConfig
}

// PortRedirectService is the main service struct
type PortRedirectService struct {
	server            *http.Server
	config            *Config
	hostsManager      *HostsManager
	logger            *log.Logger
	structuredLogger  *StructuredLogger
	logFileManager    *LogFileManager
	configWatcher     *ConfigWatcher
	securityValidator *SecurityValidator
	requestHandler    *ModeAwareHandler
	startTime         time.Time
	configLoaded      time.Time
	lastError         string
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
	Uptime            time.Duration      `json:"uptime"`
	ConfigLoaded      time.Time          `json:"config_loaded"`
	PortsConfigured   []int              `json:"ports_configured"`
	HostsStatus       HostsFileStatus    `json:"hosts_status"`
	LastError         string             `json:"last_error,omitempty"`
	DeploymentMode    string             `json:"deployment_mode"`
	WebServiceMetrics *WebServiceMetrics `json:"web_service_metrics,omitempty"`
}

// WebServiceMetrics represents web service specific metrics
type WebServiceMetrics struct {
	DomainPatterns      []string         `json:"domain_patterns"`
	RequestCount        int64            `json:"request_count"`
	SuccessfulRedirects int64            `json:"successful_redirects"`
	FailedRequests      int64            `json:"failed_requests"`
	RateLimitedRequests int64            `json:"rate_limited_requests"`
	UniqueIPs           int              `json:"unique_ips"`
	LastRequestTime     *time.Time       `json:"last_request_time,omitempty"`
	PortUsageStats      map[string]int64 `json:"port_usage_stats"`
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

// NotFoundError represents a resource not found error
type NotFoundError struct {
	Message string
}

func (e *NotFoundError) Error() string {
	return e.Message
}

// ValidationError represents a validation error
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// ConfigurationError represents a configuration error
type ConfigurationError struct {
	Message string
}

func (e *ConfigurationError) Error() string {
	return e.Message
}

// RateLimitError represents a rate limiting error
type RateLimitError struct {
	Message string
}

func (e *RateLimitError) Error() string {
	return e.Message
}

// RateLimiter interface for request rate limiting
type RateLimiter interface {
	Allow(clientIP string) bool
	Configure(rps int, burst int)
	Cleanup() // Remove old entries
}

// IPRateLimiter implements per-IP rate limiting using token bucket algorithm
type IPRateLimiter struct {
	limiters map[string]*TokenBucket
	rps      int
	burst    int
	mutex    sync.RWMutex
	logger   *StructuredLogger
}

// TokenBucket represents a token bucket for rate limiting
type TokenBucket struct {
	tokens     int
	maxTokens  int
	lastRefill time.Time
	mutex      sync.Mutex
}

// NewIPRateLimiter creates a new IP-based rate limiter
func NewIPRateLimiter(rps, burst int, logger *StructuredLogger) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*TokenBucket),
		rps:      rps,
		burst:    burst,
		logger:   logger,
	}
}

// Allow checks if a request from the given IP should be allowed
func (rl *IPRateLimiter) Allow(clientIP string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	// Get or create token bucket for this IP
	bucket, exists := rl.limiters[clientIP]
	if !exists {
		bucket = &TokenBucket{
			tokens:     rl.burst,
			maxTokens:  rl.burst,
			lastRefill: time.Now(),
		}
		rl.limiters[clientIP] = bucket
	}

	// Check if request is allowed
	allowed := bucket.consume(rl.rps)

	if rl.logger != nil {
		if allowed {
			rl.logger.LogInfo("rate_limit_allow", fmt.Sprintf("client=%s tokens_remaining=%d", clientIP, bucket.tokens))
		} else {
			rl.logger.LogWarning("rate_limit_deny", fmt.Sprintf("client=%s tokens_remaining=%d", clientIP, bucket.tokens))
		}
	}

	return allowed
}

// Configure updates the rate limiter configuration
func (rl *IPRateLimiter) Configure(rps int, burst int) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.rps = rps
	rl.burst = burst

	// Update existing buckets with new configuration
	for _, bucket := range rl.limiters {
		bucket.mutex.Lock()
		bucket.maxTokens = burst
		// If new burst is higher and bucket is empty, give it some tokens
		if bucket.tokens == 0 && burst > 0 {
			bucket.tokens = burst
			bucket.lastRefill = time.Now()
		} else if bucket.tokens > burst {
			bucket.tokens = burst
		}
		bucket.mutex.Unlock()
	}

	if rl.logger != nil {
		rl.logger.LogInfo("rate_limit_config", fmt.Sprintf("rps=%d burst=%d", rps, burst))
	}
}

// Cleanup removes old entries to prevent memory leaks
func (rl *IPRateLimiter) Cleanup() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cleanupThreshold := 5 * time.Minute // Remove entries older than 5 minutes

	var removedCount int
	for ip, bucket := range rl.limiters {
		bucket.mutex.Lock()
		if now.Sub(bucket.lastRefill) > cleanupThreshold {
			delete(rl.limiters, ip)
			removedCount++
		}
		bucket.mutex.Unlock()
	}

	if rl.logger != nil && removedCount > 0 {
		rl.logger.LogInfo("rate_limit_cleanup", fmt.Sprintf("removed_entries=%d total_entries=%d", removedCount, len(rl.limiters)))
	}
}

// consume attempts to consume a token from the bucket
func (tb *TokenBucket) consume(rps int) bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	// Refill tokens based on time elapsed
	tb.refill(rps)

	// Check if we have tokens available
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

// refill adds tokens to the bucket based on elapsed time and RPS rate
func (tb *TokenBucket) refill(rps int) {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)

	// Calculate tokens to add based on RPS (tokens per second)
	tokensToAdd := int(elapsed.Seconds() * float64(rps))

	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.maxTokens {
			tb.tokens = tb.maxTokens
		}
		tb.lastRefill = now
	}
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
	if sl.logger != nil {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		sl.logger.Printf("[REDIRECT] timestamp=%s source=%s target=%s client=%s status=%d",
			timestamp, sourceHost, targetURL, clientIP, statusCode)
	}
}

// LogSecurityRedirect logs a redirect operation with enhanced security information
func (sl *StructuredLogger) LogSecurityRedirect(sourceHost, targetURL, clientIP, userAgent, method string, statusCode int, requestID string) {
	if sl.logger != nil {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		sl.logger.Printf("[SECURITY-REDIRECT] timestamp=%s request_id=%s source=%s target=%s client=%s user_agent=%s method=%s status=%d",
			timestamp, requestID, sourceHost, targetURL, clientIP, userAgent, method, statusCode)
	}
}

// LogError logs an error with structured information
func (sl *StructuredLogger) LogError(operation, message string, err error) {
	if sl.logger != nil {
		if err != nil {
			sl.logger.Printf("[ERROR] operation=%s message=%s error=%v", operation, message, err)
		} else {
			sl.logger.Printf("[ERROR] operation=%s message=%s", operation, message)
		}
	}
}

// LogInfo logs informational messages with structured format
func (sl *StructuredLogger) LogInfo(operation, message string) {
	if sl.logger != nil {
		sl.logger.Printf("[INFO] operation=%s message=%s", operation, message)
	}
}

// LogWarning logs warning messages with structured format
func (sl *StructuredLogger) LogWarning(operation, message string) {
	if sl.logger != nil {
		sl.logger.Printf("[WARN] operation=%s message=%s", operation, message)
	}
}

// LogStartup logs service startup information
func (sl *StructuredLogger) LogStartup(version, configPath string, portCount int) {
	if sl.logger != nil {
		sl.logger.Printf("[STARTUP] service=port-redirect-service version=%s config=%s ports=%d",
			version, configPath, portCount)
	}
}

// LogShutdown logs service shutdown information
func (sl *StructuredLogger) LogShutdown(reason string, uptime time.Duration) {
	if sl.logger != nil {
		sl.logger.Printf("[SHUTDOWN] reason=%s uptime=%s", reason, uptime.String())
	}
}

// LogConfigChange logs configuration changes
func (sl *StructuredLogger) LogConfigChange(oldPortCount, newPortCount int) {
	if sl.logger != nil {
		sl.logger.Printf("[CONFIG] operation=reload old_ports=%d new_ports=%d", oldPortCount, newPortCount)
	}
}

// LogWebServiceRequest logs web service specific request information
func (sl *StructuredLogger) LogWebServiceRequest(host, clientIP string, port int, matched bool) {
	if sl.logger != nil {
		sl.logger.Printf("[WEB-SERVICE] host=%s client=%s port=%d pattern_matched=%v", host, clientIP, port, matched)
	}
}

// LogDeploymentMode logs deployment mode information
func (sl *StructuredLogger) LogDeploymentMode(mode DeploymentMode, config interface{}) {
	if sl.logger != nil {
		sl.logger.Printf("[DEPLOYMENT] mode=%s config=%+v", mode.String(), config)
	}
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

// DomainMatcher interface for domain pattern matching and port extraction
type DomainMatcher interface {
	AddPattern(pattern string) error
	MatchesPattern(host string) bool
	ExtractPort(host string) (int, bool)
	ValidatePatterns() error
	GetPatterns() []string
}

// PatternMatcher implements DomainMatcher interface with regex-based matching
type PatternMatcher struct {
	patterns       []string
	compiledRegexs []*regexp.Regexp
	logger         *StructuredLogger
}

// NewPatternMatcher creates a new PatternMatcher instance
func NewPatternMatcher(logger *StructuredLogger) *PatternMatcher {
	return &PatternMatcher{
		patterns:       make([]string, 0),
		compiledRegexs: make([]*regexp.Regexp, 0),
		logger:         logger,
	}
}

// AddPattern adds a domain pattern to the matcher
func (pm *PatternMatcher) AddPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("domain pattern cannot be empty")
	}

	// Validate the pattern format
	if err := validateDomainPattern(pattern); err != nil {
		return fmt.Errorf("invalid domain pattern '%s': %w", pattern, err)
	}

	// Convert wildcard pattern to regex
	regexPattern, err := pm.convertPatternToRegex(pattern)
	if err != nil {
		return fmt.Errorf("failed to convert pattern '%s' to regex: %w", pattern, err)
	}

	// Compile the regex
	compiledRegex, err := regexp.Compile(regexPattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex for pattern '%s': %w", pattern, err)
	}

	// Add to patterns and compiled regexes
	pm.patterns = append(pm.patterns, pattern)
	pm.compiledRegexs = append(pm.compiledRegexs, compiledRegex)

	if pm.logger != nil {
		pm.logger.LogInfo("domain_pattern_added", fmt.Sprintf("pattern=%s regex=%s", pattern, regexPattern))
	}

	return nil
}

// MatchesPattern checks if a host matches any of the configured patterns
func (pm *PatternMatcher) MatchesPattern(host string) bool {
	if host == "" {
		return false
	}

	// Remove port suffix if present (e.g., "3000.example.com:8080" -> "3000.example.com")
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// Check against all compiled regex patterns
	for i, regex := range pm.compiledRegexs {
		if regex.MatchString(host) {
			if pm.logger != nil {
				pm.logger.LogInfo("domain_pattern_matched", fmt.Sprintf("host=%s pattern=%s", host, pm.patterns[i]))
			}
			return true
		}
	}

	return false
}

// ExtractPort extracts port number from subdomain format for web service mode
func (pm *PatternMatcher) ExtractPort(host string) (int, bool) {
	if host == "" {
		return 0, false
	}

	// Remove port suffix if present
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// Check if host matches any pattern and extract port
	for i, regex := range pm.compiledRegexs {
		matches := regex.FindStringSubmatch(host)
		if len(matches) >= 2 {
			// The first capture group should contain the port number
			portStr := matches[1]
			port, err := strconv.Atoi(portStr)
			if err != nil {
				if pm.logger != nil {
					pm.logger.LogWarning("port_extraction_failed", fmt.Sprintf("host=%s pattern=%s port_str=%s error=%v", host, pm.patterns[i], portStr, err))
				}
				continue
			}

			if pm.logger != nil {
				pm.logger.LogInfo("port_extracted", fmt.Sprintf("host=%s pattern=%s port=%d", host, pm.patterns[i], port))
			}
			return port, true
		}
	}

	return 0, false
}

// ValidatePatterns validates all configured patterns
func (pm *PatternMatcher) ValidatePatterns() error {
	if len(pm.patterns) == 0 {
		return fmt.Errorf("no domain patterns configured")
	}

	for i, pattern := range pm.patterns {
		if err := validateDomainPattern(pattern); err != nil {
			return fmt.Errorf("invalid pattern %d (%s): %w", i+1, pattern, err)
		}
	}

	return nil
}

// GetPatterns returns a copy of the configured patterns
func (pm *PatternMatcher) GetPatterns() []string {
	patterns := make([]string, len(pm.patterns))
	copy(patterns, pm.patterns)
	return patterns
}

// convertPatternToRegex converts a wildcard domain pattern to a regex pattern
func (pm *PatternMatcher) convertPatternToRegex(pattern string) (string, error) {
	// Escape special regex characters except for our wildcard
	escaped := regexp.QuoteMeta(pattern)

	// Replace escaped wildcard with regex equivalent
	// QuoteMeta will escape * to \*, so we replace \* with our port capture group
	if strings.HasPrefix(pattern, "*.") {
		// For patterns like "*.example.com", create regex like "^(\d+)\.example\.com$"
		domainPart := strings.TrimPrefix(pattern, "*")
		escapedDomain := regexp.QuoteMeta(domainPart)
		regexPattern := fmt.Sprintf("^(\\d+)%s$", escapedDomain)
		return regexPattern, nil
	} else {
		// For exact patterns without wildcards, we still need to capture the port
		// This handles cases where someone specifies an exact subdomain pattern
		// We'll assume the pattern should match exactly but still extract port if it's in subdomain format
		parts := strings.Split(pattern, ".")
		if len(parts) >= 2 {
			// Check if the first part could be a port placeholder
			firstPart := parts[0]
			if firstPart == "*" || strings.Contains(firstPart, "port") || strings.Contains(firstPart, "PORT") {
				// Replace the first part with port capture group
				parts[0] = "(\\d+)"
				regexPattern := fmt.Sprintf("^%s$", strings.Join(parts, "\\."))
				return regexPattern, nil
			}
		}

		// For patterns without port placeholders, just match exactly
		regexPattern := fmt.Sprintf("^%s$", escaped)
		return regexPattern, nil
	}
}

// ConfigWatcher watches for configuration file changes
type ConfigWatcher struct {
	configPath  string
	lastModTime time.Time
	stopChan    chan struct{}
	reloadChan  chan []int
	errorChan   chan error
	logger      *log.Logger
}

// parseConfigFile reads and parses the configuration file with enhanced format support
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

		// Skip configuration key-value pairs (contain '=')
		if strings.Contains(line, "=") {
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

# Deployment mode: local or web (default: local)
mode=local

# Web service specific settings (only used in web mode)
# web_port=8080
# domain_patterns=*.sankalpmukim.dev,*.example.com

# Rate limiting (optional, only used in web mode)
# enable_rate_limit=false
# rate_limit_rps=100

# Local mode specific settings (only used in local mode)
# hosts_file_path=/etc/hosts
# backup_path=/etc/port-redirect/hosts.backup
# listen_port=80
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

// parseDeploymentConfig parses the deployment configuration from a config file with enhanced format support
func parseDeploymentConfig(configPath string) (*DeploymentConfig, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	config := &DeploymentConfig{
		Mode: LocalMode, // Default to local mode for backward compatibility
		LocalConfig: &LocalModeConfig{
			HostsFilePath: DefaultHostsPath,
			BackupPath:    DefaultBackupPath,
			ListenPort:    80,
		},
		WebConfig: &WebServiceConfig{
			Port:           8080,
			DomainPatterns: []string{},
			RateLimit: struct {
				Enabled bool `json:"enabled"`
				RPS     int  `json:"rps"`
				Burst   int  `json:"burst"`
			}{
				Enabled: false,
				RPS:     100,
				Burst:   10,
			},
		},
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	hasConfigurationKeys := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip port numbers (handled by parseConfigFile)
		if _, err := strconv.Atoi(line); err == nil {
			continue
		}

		// Parse key=value pairs
		if strings.Contains(line, "=") {
			hasConfigurationKeys = true
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if err := parseConfigKeyValue(config, key, value, lineNum); err != nil {
				return nil, err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// If no configuration keys were found, this is a legacy config file
	// Apply backward compatibility defaults
	if !hasConfigurationKeys {
		config = applyBackwardCompatibilityDefaults(config)
	}

	return config, nil
}

// applyBackwardCompatibilityDefaults applies defaults for legacy configuration files
func applyBackwardCompatibilityDefaults(config *DeploymentConfig) *DeploymentConfig {
	// For legacy configs (no key=value pairs), ensure local mode with proper defaults
	config.Mode = LocalMode

	// Ensure LocalConfig exists with proper defaults
	if config.LocalConfig == nil {
		config.LocalConfig = &LocalModeConfig{}
	}

	// Apply default values if not set
	if config.LocalConfig.HostsFilePath == "" {
		config.LocalConfig.HostsFilePath = DefaultHostsPath
	}
	if config.LocalConfig.BackupPath == "" {
		config.LocalConfig.BackupPath = DefaultBackupPath
	}
	if config.LocalConfig.ListenPort == 0 {
		config.LocalConfig.ListenPort = 80
	}

	return config
}

// parseConfigKeyValue parses individual key-value pairs from the config file with enhanced validation
func parseConfigKeyValue(config *DeploymentConfig, key, value string, lineNum int) error {
	switch strings.ToLower(key) {
	case "mode", "deployment_mode":
		mode, err := ParseDeploymentMode(value)
		if err != nil {
			return fmt.Errorf("invalid deployment mode on line %d: %w", lineNum, err)
		}
		config.Mode = mode

	case "web_port", "webport", "web_service_port":
		if config.WebConfig == nil {
			config.WebConfig = &WebServiceConfig{}
		}
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid web port on line %d: %w", lineNum, err)
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("web port %d on line %d is out of valid range (1-65535)", port, lineNum)
		}
		config.WebConfig.Port = port

	case "domain_patterns", "domainpatterns", "domains":
		if config.WebConfig == nil {
			config.WebConfig = &WebServiceConfig{}
		}
		if value == "" {
			config.WebConfig.DomainPatterns = []string{}
		} else {
			patterns := strings.Split(value, ",")
			for i, pattern := range patterns {
				patterns[i] = strings.TrimSpace(pattern)
			}
			// Validate each pattern
			for _, pattern := range patterns {
				if pattern != "" {
					if err := validateDomainPattern(pattern); err != nil {
						return fmt.Errorf("invalid domain pattern '%s' on line %d: %w", pattern, lineNum, err)
					}
				}
			}
			config.WebConfig.DomainPatterns = patterns
		}

	case "enable_rate_limit", "enableratelimit", "rate_limit_enabled":
		if config.WebConfig == nil {
			config.WebConfig = &WebServiceConfig{}
		}
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid rate limit enable value on line %d: %w", lineNum, err)
		}
		config.WebConfig.RateLimit.Enabled = enabled

	case "rate_limit_rps", "ratelimitrps", "rate_limit_requests_per_second":
		if config.WebConfig == nil {
			config.WebConfig = &WebServiceConfig{}
		}
		rps, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid rate limit RPS on line %d: %w", lineNum, err)
		}
		if rps < 1 {
			return fmt.Errorf("rate limit RPS must be positive on line %d", lineNum)
		}
		config.WebConfig.RateLimit.RPS = rps

	case "rate_limit_burst", "ratelimitburst":
		if config.WebConfig == nil {
			config.WebConfig = &WebServiceConfig{}
		}
		burst, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid rate limit burst on line %d: %w", lineNum, err)
		}
		if burst < 1 {
			return fmt.Errorf("rate limit burst must be positive on line %d", lineNum)
		}
		config.WebConfig.RateLimit.Burst = burst

	case "hosts_file_path", "hostsfilepath", "hosts_path":
		if config.LocalConfig == nil {
			config.LocalConfig = &LocalModeConfig{}
		}
		if value == "" {
			return fmt.Errorf("hosts file path cannot be empty on line %d", lineNum)
		}
		config.LocalConfig.HostsFilePath = value

	case "backup_path", "backuppath", "hosts_backup_path":
		if config.LocalConfig == nil {
			config.LocalConfig = &LocalModeConfig{}
		}
		if value == "" {
			return fmt.Errorf("backup path cannot be empty on line %d", lineNum)
		}
		config.LocalConfig.BackupPath = value

	case "listen_port", "listenport", "local_port":
		if config.LocalConfig == nil {
			config.LocalConfig = &LocalModeConfig{}
		}
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid listen port on line %d: %w", lineNum, err)
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("listen port %d on line %d is out of valid range (1-65535)", port, lineNum)
		}
		config.LocalConfig.ListenPort = port

	default:
		// Ignore unknown configuration keys for forward compatibility
		// This allows new configuration options to be added without breaking older versions
	}

	return nil
}

// validateDeploymentConfig validates the deployment configuration
func validateDeploymentConfig(config *DeploymentConfig) error {
	if config == nil {
		return fmt.Errorf("deployment configuration is nil")
	}

	switch config.Mode {
	case LocalMode:
		if config.LocalConfig == nil {
			return fmt.Errorf("local mode configuration is missing")
		}
		return validateLocalModeConfig(config.LocalConfig)

	case WebServiceMode:
		if config.WebConfig == nil {
			return fmt.Errorf("web service mode configuration is missing")
		}
		return validateWebServiceConfig(config.WebConfig)

	default:
		return fmt.Errorf("invalid deployment mode: %v", config.Mode)
	}
}

// validateLocalModeConfig validates local mode specific configuration
func validateLocalModeConfig(config *LocalModeConfig) error {
	if config == nil {
		return fmt.Errorf("local mode configuration is nil")
	}

	if config.HostsFilePath == "" {
		return fmt.Errorf("hosts file path cannot be empty")
	}

	if config.BackupPath == "" {
		return fmt.Errorf("backup path cannot be empty")
	}

	if config.ListenPort < 1 || config.ListenPort > 65535 {
		return fmt.Errorf("listen port %d is out of valid range (1-65535)", config.ListenPort)
	}

	return nil
}

// validateWebServiceConfig validates web service mode specific configuration
func validateWebServiceConfig(config *WebServiceConfig) error {
	if config == nil {
		return fmt.Errorf("web service configuration is nil")
	}

	if config.Port < 1 || config.Port > 65535 {
		return fmt.Errorf("web service port %d is out of valid range (1-65535)", config.Port)
	}

	if len(config.DomainPatterns) == 0 {
		return fmt.Errorf("web service mode requires at least one domain pattern")
	}

	// Validate domain patterns
	for i, pattern := range config.DomainPatterns {
		if err := validateDomainPattern(pattern); err != nil {
			return fmt.Errorf("invalid domain pattern %d (%s): %w", i+1, pattern, err)
		}
	}

	// Validate rate limiting configuration
	if config.RateLimit.Enabled {
		if config.RateLimit.RPS < 1 {
			return fmt.Errorf("rate limit RPS must be positive when rate limiting is enabled")
		}
		if config.RateLimit.Burst < 1 {
			return fmt.Errorf("rate limit burst must be positive when rate limiting is enabled")
		}
	}

	return nil
}

// validateDomainPattern validates a domain pattern for web service mode
func validateDomainPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("domain pattern cannot be empty")
	}

	// Basic validation - check for valid characters and format
	// Allow wildcards (*), alphanumeric characters, dots, and hyphens
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9.*-]+$`)
	if !validPattern.MatchString(pattern) {
		return fmt.Errorf("domain pattern contains invalid characters")
	}

	// Ensure pattern has at least one dot (for TLD)
	if !strings.Contains(pattern, ".") {
		return fmt.Errorf("domain pattern must contain at least one dot")
	}

	// Validate that wildcard is only at the beginning and only one wildcard
	if strings.Contains(pattern, "*") {
		if !strings.HasPrefix(pattern, "*.") {
			return fmt.Errorf("wildcard (*) can only be used at the beginning of the pattern")
		}
		// Check for multiple wildcards
		if strings.Count(pattern, "*") > 1 {
			return fmt.Errorf("wildcard (*) can only be used at the beginning of the pattern")
		}
	}

	return nil
}

// loadFullConfig loads both ports and deployment configuration
func loadFullConfig(configPath string) ([]int, *DeploymentConfig, error) {
	// Load ports
	ports, err := loadConfig(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load ports: %w", err)
	}

	// Load deployment configuration
	deploymentConfig, err := parseDeploymentConfig(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load deployment config: %w", err)
	}

	// Validate deployment configuration
	if err := validateDeploymentConfig(deploymentConfig); err != nil {
		return nil, nil, fmt.Errorf("invalid deployment configuration: %w", err)
	}

	return ports, deploymentConfig, nil
}

// ConfigMigration represents a configuration migration operation
type ConfigMigration struct {
	FromVersion string
	ToVersion   string
	Description string
	MigrateFunc func(configPath string) error
}

// ConfigMigrationManager manages configuration file migrations
type ConfigMigrationManager struct {
	migrations []ConfigMigration
	logger     *StructuredLogger
}

// NewConfigMigrationManager creates a new configuration migration manager
func NewConfigMigrationManager(logger *StructuredLogger) *ConfigMigrationManager {
	manager := &ConfigMigrationManager{
		migrations: make([]ConfigMigration, 0),
		logger:     logger,
	}

	// Register available migrations
	manager.registerMigrations()

	return manager
}

// registerMigrations registers all available configuration migrations
func (cmm *ConfigMigrationManager) registerMigrations() {
	// Migration from legacy format (ports only) to enhanced format
	cmm.migrations = append(cmm.migrations, ConfigMigration{
		FromVersion: "legacy",
		ToVersion:   "v1.0",
		Description: "Migrate from legacy port-only format to enhanced configuration format",
		MigrateFunc: cmm.migrateLegacyToV1,
	})
}

// migrateLegacyToV1 migrates a legacy configuration file to v1.0 format
func (cmm *ConfigMigrationManager) migrateLegacyToV1(configPath string) error {
	// Read the existing configuration
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Check if this is already a v1.0+ config (contains key=value pairs)
	if strings.Contains(string(content), "=") {
		return fmt.Errorf("configuration file already appears to be in enhanced format")
	}

	// Create backup of original file
	backupPath := configPath + ".backup." + fmt.Sprintf("%d", time.Now().Unix())
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	if cmm.logger != nil {
		cmm.logger.LogInfo("config_migration", fmt.Sprintf("Created backup at %s", backupPath))
	}

	// Parse existing ports
	ports, err := parseConfigFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to parse existing config: %w", err)
	}

	// Generate new configuration content with enhanced format
	var newContent strings.Builder

	// Add header comment
	newContent.WriteString("# Port Redirect Service Configuration\n")
	newContent.WriteString("# Migrated from legacy format on " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	newContent.WriteString("# Original backup saved as: " + filepath.Base(backupPath) + "\n\n")

	// Add deployment mode configuration
	newContent.WriteString("# Deployment mode: local or web (default: local)\n")
	newContent.WriteString("mode=local\n\n")

	// Add web service configuration section (commented out by default)
	newContent.WriteString("# Web service specific settings (only used in web mode)\n")
	newContent.WriteString("# web_port=8080\n")
	newContent.WriteString("# domain_patterns=*.sankalpmukim.dev,*.example.com\n\n")

	// Add rate limiting configuration (commented out by default)
	newContent.WriteString("# Rate limiting (optional, only used in web mode)\n")
	newContent.WriteString("# enable_rate_limit=false\n")
	newContent.WriteString("# rate_limit_rps=100\n")
	newContent.WriteString("# rate_limit_burst=10\n\n")

	// Add local mode configuration (commented out, using defaults)
	newContent.WriteString("# Local mode specific settings (only used in local mode)\n")
	newContent.WriteString("# hosts_file_path=/etc/hosts\n")
	newContent.WriteString("# backup_path=/etc/port-redirect/hosts.backup\n")
	newContent.WriteString("# listen_port=80\n\n")

	// Add existing ports
	newContent.WriteString("# Configured ports (one per line)\n")
	for _, port := range ports {
		newContent.WriteString(fmt.Sprintf("%d\n", port))
	}

	// Write the new configuration
	if err := os.WriteFile(configPath, []byte(newContent.String()), 0644); err != nil {
		return fmt.Errorf("failed to write migrated config: %w", err)
	}

	if cmm.logger != nil {
		cmm.logger.LogInfo("config_migration", fmt.Sprintf("Successfully migrated configuration from legacy format to v1.0"))
	}

	return nil
}

// DetectConfigVersion detects the version of a configuration file
func (cmm *ConfigMigrationManager) DetectConfigVersion(configPath string) (string, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	contentStr := string(content)

	// Check for version markers or format indicators
	if strings.Contains(contentStr, "mode=") || strings.Contains(contentStr, "web_port=") {
		return "v1.0", nil
	}

	// If no key=value pairs found, it's legacy format
	if !strings.Contains(contentStr, "=") {
		return "legacy", nil
	}

	// Default to v1.0 if we can't determine
	return "v1.0", nil
}

// NeedsMigration checks if a configuration file needs migration
func (cmm *ConfigMigrationManager) NeedsMigration(configPath string) (bool, string, error) {
	version, err := cmm.DetectConfigVersion(configPath)
	if err != nil {
		return false, "", err
	}

	// Check if we have a migration for this version
	for _, migration := range cmm.migrations {
		if migration.FromVersion == version {
			return true, migration.ToVersion, nil
		}
	}

	return false, version, nil
}

// MigrateConfig performs configuration migration if needed
func (cmm *ConfigMigrationManager) MigrateConfig(configPath string) error {
	needsMigration, targetVersion, err := cmm.NeedsMigration(configPath)
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}

	if !needsMigration {
		if cmm.logger != nil {
			cmm.logger.LogInfo("config_migration", "Configuration file is already in current format")
		}
		return nil
	}

	// Find and execute the appropriate migration
	for _, migration := range cmm.migrations {
		currentVersion, _ := cmm.DetectConfigVersion(configPath)
		if migration.FromVersion == currentVersion {
			if cmm.logger != nil {
				cmm.logger.LogInfo("config_migration", fmt.Sprintf("Starting migration from %s to %s: %s",
					migration.FromVersion, migration.ToVersion, migration.Description))
			}

			if err := migration.MigrateFunc(configPath); err != nil {
				return fmt.Errorf("migration failed: %w", err)
			}

			if cmm.logger != nil {
				cmm.logger.LogInfo("config_migration", fmt.Sprintf("Successfully migrated to %s", targetVersion))
			}

			return nil
		}
	}

	return fmt.Errorf("no migration found for current configuration version")
}

// ValidateConfigFormat validates the format and structure of a configuration file
func ValidateConfigFormat(configPath string) error {
	// Try to parse both ports and deployment config
	_, err := parseConfigFile(configPath)
	if err != nil {
		return fmt.Errorf("invalid port configuration: %w", err)
	}

	deploymentConfig, err := parseDeploymentConfig(configPath)
	if err != nil {
		return fmt.Errorf("invalid deployment configuration: %w", err)
	}

	// Validate the deployment configuration
	if err := validateDeploymentConfig(deploymentConfig); err != nil {
		return fmt.Errorf("invalid deployment configuration: %w", err)
	}

	return nil
}

// CreateConfigTemplate creates a template configuration file with examples
func CreateConfigTemplate(configPath string, mode DeploymentMode) error {
	var content strings.Builder

	// Add header
	content.WriteString("# Port Redirect Service Configuration\n")
	content.WriteString("# Generated on " + time.Now().Format("2006-01-02 15:04:05") + "\n\n")

	// Add deployment mode
	content.WriteString("# Deployment mode: local or web\n")
	content.WriteString(fmt.Sprintf("mode=%s\n\n", mode.String()))

	if mode == WebServiceMode {
		// Web service configuration
		content.WriteString("# Web service specific settings\n")
		content.WriteString("web_port=8080\n")
		content.WriteString("domain_patterns=*.example.com,*.dev.local\n\n")

		content.WriteString("# Rate limiting (optional)\n")
		content.WriteString("enable_rate_limit=false\n")
		content.WriteString("rate_limit_rps=100\n")
		content.WriteString("rate_limit_burst=10\n\n")

		// Local mode settings (commented out for web mode)
		content.WriteString("# Local mode specific settings (not used in web mode)\n")
		content.WriteString("# hosts_file_path=/etc/hosts\n")
		content.WriteString("# backup_path=/etc/port-redirect/hosts.backup\n")
		content.WriteString("# listen_port=80\n\n")
	} else {
		// Local mode configuration
		content.WriteString("# Local mode specific settings\n")
		content.WriteString("hosts_file_path=/etc/hosts\n")
		content.WriteString("backup_path=/etc/port-redirect/hosts.backup\n")
		content.WriteString("listen_port=80\n\n")

		// Web service settings (commented out for local mode)
		content.WriteString("# Web service specific settings (not used in local mode)\n")
		content.WriteString("# web_port=8080\n")
		content.WriteString("# domain_patterns=*.example.com,*.dev.local\n")
		content.WriteString("# enable_rate_limit=false\n")
		content.WriteString("# rate_limit_rps=100\n\n")
	}

	// Add default ports
	content.WriteString("# Configured ports (one per line)\n")
	content.WriteString("# Common development ports:\n")
	content.WriteString("3000\n")
	content.WriteString("8080\n")
	content.WriteString("5173\n")
	content.WriteString("9000\n")

	// Write the template
	if err := os.WriteFile(configPath, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to create config template: %w", err)
	}

	return nil
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
// This function supports both local mode (fixed TLD patterns) and web service mode (configurable domain patterns)
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

// extractPortFromHostWithDomainMatcher extracts port number from Host header using domain matcher
// This function is specifically designed for web service mode with configurable domain patterns
// Returns the port number, extraction success, and any validation errors
func extractPortFromHostWithDomainMatcher(host string, domainMatcher DomainMatcher) (int, bool, error) {
	if host == "" {
		return 0, false, &ValidationError{Message: "host header cannot be empty"}
	}

	// Validate domain pattern before port extraction
	if !domainMatcher.MatchesPattern(host) {
		return 0, false, &NotFoundError{Message: fmt.Sprintf("host %s does not match any configured domain patterns", host)}
	}

	// Extract port using domain matcher
	port, extracted := domainMatcher.ExtractPort(host)
	if !extracted {
		return 0, false, &ValidationError{Message: fmt.Sprintf("could not extract port from host: %s", host)}
	}

	// Validate port range
	if !validatePort(port) {
		return 0, false, &ValidationError{Message: fmt.Sprintf("port %d is out of valid range (1-65535)", port)}
	}

	return port, true, nil
}

// validatePortInConfiguredList checks if the extracted port is in the configured ports list
// Returns true if port is configured, false otherwise
func validatePortInConfiguredList(port int, configuredPorts []int) bool {
	return isPortConfigured(port, configuredPorts)
}

// extractAndValidatePort performs comprehensive port extraction and validation
// This function combines domain validation, port extraction, range validation, and configuration validation
// Returns the port number and any validation errors
func extractAndValidatePort(host string, configuredPorts []int, domainMatcher DomainMatcher, mode DeploymentMode) (int, error) {
	var port int
	var extracted bool
	var err error

	switch mode {
	case LocalMode:
		// Use legacy extraction for local mode
		port, extracted = extractPortFromHost(host)
		if !extracted {
			return 0, &NotFoundError{Message: fmt.Sprintf("invalid host format: %s", host)}
		}
	case WebServiceMode:
		// Use enhanced extraction with domain matcher for web service mode
		if domainMatcher == nil {
			return 0, &ConfigurationError{Message: "domain matcher not configured for web service mode"}
		}

		port, extracted, err = extractPortFromHostWithDomainMatcher(host, domainMatcher)
		if err != nil {
			return 0, err
		}
		if !extracted {
			return 0, &ValidationError{Message: fmt.Sprintf("could not extract port from host: %s", host)}
		}
	default:
		return 0, &ConfigurationError{Message: fmt.Sprintf("unsupported deployment mode: %v", mode)}
	}

	// Validate port range (common for both modes)
	if !validatePort(port) {
		return 0, &ValidationError{Message: fmt.Sprintf("port %d is out of valid range (1-65535)", port)}
	}

	// Validate port against configured list (common for both modes)
	if !validatePortInConfiguredList(port, configuredPorts) {
		return 0, &NotFoundError{Message: fmt.Sprintf("port %d not configured", port)}
	}

	return port, nil
}

// validatePort checks if the port number is within valid range (1-65535)
func validatePort(port int) bool {
	return port >= 1 && port <= 65535
}

// RequestHandler interface for handling HTTP requests
type RequestHandler interface {
	HandleRequest(w http.ResponseWriter, r *http.Request)
	ValidateRequest(r *http.Request) error
	ProcessRedirect(host string, configuredPorts []int) (string, int, error)
}

// ModeAwareHandler routes requests based on deployment mode
type ModeAwareHandler struct {
	mode         DeploymentMode
	localHandler RequestHandler
	webHandler   RequestHandler
	logger       *StructuredLogger
}

// NewModeAwareHandler creates a new ModeAwareHandler instance
func NewModeAwareHandler(mode DeploymentMode, config *Config, logger *StructuredLogger, securityValidator *SecurityValidator) *ModeAwareHandler {
	var localHandler, webHandler RequestHandler

	// Create local handler (existing functionality)
	localHandler = NewLocalHandler(config, logger, securityValidator)

	// Create web service handler if needed
	if mode == WebServiceMode {
		domainMatcher := NewPatternMatcher(logger)
		for _, pattern := range config.DomainPatterns {
			if err := domainMatcher.AddPattern(pattern); err != nil {
				logger.LogError("domain_pattern_error", fmt.Sprintf("Failed to add pattern %s: %v", pattern, err), err)
			}
		}
		webHandler = NewWebServiceHandler(domainMatcher, config, logger, securityValidator)
	}

	return &ModeAwareHandler{
		mode:         mode,
		localHandler: localHandler,
		webHandler:   webHandler,
		logger:       logger,
	}
}

// HandleRequest routes the request to the appropriate handler based on deployment mode
func (mah *ModeAwareHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	switch mah.mode {
	case LocalMode:
		if mah.localHandler != nil {
			mah.localHandler.HandleRequest(w, r)
		} else {
			mah.logger.LogError("handler_error", "Local handler not initialized", nil)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	case WebServiceMode:
		if mah.webHandler != nil {
			mah.webHandler.HandleRequest(w, r)
		} else {
			mah.logger.LogError("handler_error", "Web service handler not initialized", nil)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	default:
		mah.logger.LogError("handler_error", fmt.Sprintf("Unknown deployment mode: %v", mah.mode), nil)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// ValidateRequest validates the request based on deployment mode
func (mah *ModeAwareHandler) ValidateRequest(r *http.Request) error {
	switch mah.mode {
	case LocalMode:
		if mah.localHandler != nil {
			return mah.localHandler.ValidateRequest(r)
		}
	case WebServiceMode:
		if mah.webHandler != nil {
			return mah.webHandler.ValidateRequest(r)
		}
	}
	return fmt.Errorf("no handler available for mode %v", mah.mode)
}

// ProcessRedirect processes redirect logic based on deployment mode
func (mah *ModeAwareHandler) ProcessRedirect(host string, configuredPorts []int) (string, int, error) {
	switch mah.mode {
	case LocalMode:
		if mah.localHandler != nil {
			return mah.localHandler.ProcessRedirect(host, configuredPorts)
		}
	case WebServiceMode:
		if mah.webHandler != nil {
			return mah.webHandler.ProcessRedirect(host, configuredPorts)
		}
	}
	return "", 0, fmt.Errorf("no handler available for mode %v", mah.mode)
}

// LocalHandler handles requests in local mode (existing functionality)
type LocalHandler struct {
	config            *Config
	logger            *StructuredLogger
	securityValidator *SecurityValidator
}

// NewLocalHandler creates a new LocalHandler instance
func NewLocalHandler(config *Config, logger *StructuredLogger, securityValidator *SecurityValidator) *LocalHandler {
	return &LocalHandler{
		config:            config,
		logger:            logger,
		securityValidator: securityValidator,
	}
}

// HandleRequest handles HTTP requests in local mode
func (lh *LocalHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	clientIP := getClientIPFromRequest(r)
	requestID := lh.securityValidator.GenerateRequestID()

	// Log the incoming request with security information
	lh.securityValidator.LogSecurityRequest(r, requestID, "received", 0)

	// Validate request
	if err := lh.ValidateRequest(r); err != nil {
		lh.securityValidator.LogSecurityEvent("invalid_request", clientIP, host, err.Error())
		lh.securityValidator.CreateSafeErrorResponse(w, r, err, http.StatusBadRequest, requestID)
		lh.logger.LogRedirect(host, "none", clientIP, http.StatusBadRequest)
		return
	}

	// Process redirect
	redirectURL, port, err := lh.ProcessRedirect(host, lh.config.Ports)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch err.(type) {
		case *NotFoundError:
			statusCode = http.StatusNotFound
		case *ValidationError:
			statusCode = http.StatusBadRequest
		default:
			if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "security") {
				statusCode = http.StatusBadRequest
			}
		}
		lh.securityValidator.CreateSafeErrorResponse(w, r, err, statusCode, requestID)
		lh.logger.LogRedirect(host, "none", clientIP, statusCode)
		return
	}

	// Validate the redirect URL for security
	if err := lh.securityValidator.ValidateLocalhostRedirect(redirectURL); err != nil {
		lh.securityValidator.LogSecurityEvent("invalid_redirect_url", clientIP, host, err.Error())
		lh.securityValidator.CreateSafeErrorResponse(w, r, err, http.StatusInternalServerError, requestID)
		return
	}

	// Log successful redirect with security information
	lh.logger.LogRedirect(host, redirectURL, clientIP, http.StatusMovedPermanently)
	lh.securityValidator.LogSecurityRequest(r, requestID, "success", port)

	// Set comprehensive security headers and redirect
	lh.securityValidator.SetSecurityHeaders(w)
	w.Header().Set("X-Request-ID", requestID)
	http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
}

// ValidateRequest validates the request for local mode
func (lh *LocalHandler) ValidateRequest(r *http.Request) error {
	// Validate request parameters for security
	if err := lh.securityValidator.ValidateRequestParameters(r); err != nil {
		return fmt.Errorf("invalid request parameters: %w", err)
	}

	// Validate host header for security issues
	if err := lh.securityValidator.ValidateHostHeader(r.Host); err != nil {
		return fmt.Errorf("invalid host header: %w", err)
	}

	return nil
}

// ProcessRedirect processes redirect logic for local mode
func (lh *LocalHandler) ProcessRedirect(host string, configuredPorts []int) (string, int, error) {
	// Use enhanced port extraction and validation for local mode
	port, err := extractAndValidatePort(host, configuredPorts, nil, LocalMode)
	if err != nil {
		return "", 0, err
	}

	// Validate redirect target for security (localhost-only with configured ports)
	if err := lh.securityValidator.ValidateRedirectTarget(port, configuredPorts); err != nil {
		return "", 0, fmt.Errorf("invalid redirect target: %w", err)
	}

	// Generate localhost-only redirect URL
	redirectURL := fmt.Sprintf("http://localhost:%d", port)
	return redirectURL, port, nil
}

// setSecurityHeaders sets security headers for the response (deprecated - use SecurityValidator.SetSecurityHeaders)
func (lh *LocalHandler) setSecurityHeaders(w http.ResponseWriter) {
	lh.securityValidator.SetSecurityHeaders(w)
}

// WebServiceHandler handles requests in web service mode
type WebServiceHandler struct {
	domainMatcher     DomainMatcher
	config            *Config
	logger            *StructuredLogger
	securityValidator *SecurityValidator
	rateLimiter       RateLimiter
	metrics           *WebServiceMetrics
	metricsMutex      sync.RWMutex
}

// NewWebServiceHandler creates a new WebServiceHandler instance
func NewWebServiceHandler(domainMatcher DomainMatcher, config *Config, logger *StructuredLogger, securityValidator *SecurityValidator) *WebServiceHandler {
	var rateLimiter RateLimiter
	if config.EnableRateLimit {
		// Get burst configuration from deployment config, default to 10 if not set
		burst := 10
		if config.DeploymentConfig != nil && config.DeploymentConfig.WebConfig != nil {
			if config.DeploymentConfig.WebConfig.RateLimit.Burst > 0 {
				burst = config.DeploymentConfig.WebConfig.RateLimit.Burst
			}
		}
		rateLimiter = NewIPRateLimiter(config.RateLimitRPS, burst, logger)
	}

	// Initialize metrics
	metrics := &WebServiceMetrics{
		DomainPatterns:      domainMatcher.GetPatterns(),
		RequestCount:        0,
		SuccessfulRedirects: 0,
		FailedRequests:      0,
		RateLimitedRequests: 0,
		UniqueIPs:           0,
		PortUsageStats:      make(map[string]int64),
	}

	return &WebServiceHandler{
		domainMatcher:     domainMatcher,
		config:            config,
		logger:            logger,
		securityValidator: securityValidator,
		rateLimiter:       rateLimiter,
		metrics:           metrics,
	}
}

// HandleRequest handles HTTP requests in web service mode
func (wsh *WebServiceHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	clientIP := getClientIPFromRequest(r)
	requestID := wsh.securityValidator.GenerateRequestID()

	// Track the incoming request
	wsh.TrackRequest(clientIP)

	// Log the incoming request with security information
	wsh.securityValidator.LogSecurityRequest(r, requestID, "received", 0)

	// Validate request
	if err := wsh.ValidateRequest(r); err != nil {
		wsh.TrackFailedRequest()
		wsh.securityValidator.LogSecurityEvent("invalid_web_request", clientIP, host, err.Error())
		wsh.securityValidator.CreateSafeErrorResponse(w, r, err, http.StatusBadRequest, requestID)
		wsh.logger.LogRedirect(host, "none", clientIP, http.StatusBadRequest)
		return
	}

	// Apply rate limiting if enabled
	if wsh.rateLimiter != nil {
		if !wsh.rateLimiter.Allow(clientIP) {
			wsh.TrackRateLimitedRequest()
			rateLimitErr := &RateLimitError{Message: "Rate limit exceeded"}
			wsh.securityValidator.LogSecurityEvent("rate_limit_exceeded", clientIP, host, "Request rate limit exceeded")
			wsh.securityValidator.CreateSafeErrorResponse(w, r, rateLimitErr, http.StatusTooManyRequests, requestID)
			wsh.logger.LogRedirect(host, "none", clientIP, http.StatusTooManyRequests)
			return
		}
	}

	// Process redirect
	redirectURL, port, err := wsh.ProcessRedirect(host, wsh.config.Ports)
	if err != nil {
		wsh.TrackFailedRequest()
		statusCode := http.StatusInternalServerError
		switch err.(type) {
		case *NotFoundError:
			statusCode = http.StatusNotFound
		case *ValidationError:
			statusCode = http.StatusBadRequest
		default:
			if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "security") {
				statusCode = http.StatusBadRequest
			}
		}
		wsh.securityValidator.CreateSafeErrorResponse(w, r, err, statusCode, requestID)
		wsh.logger.LogRedirect(host, "none", clientIP, statusCode)
		return
	}

	// Validate the redirect URL for security
	if err := wsh.securityValidator.ValidateLocalhostRedirect(redirectURL); err != nil {
		wsh.securityValidator.LogSecurityEvent("invalid_redirect_url", clientIP, host, err.Error())
		wsh.securityValidator.CreateSafeErrorResponse(w, r, err, http.StatusInternalServerError, requestID)
		return
	}

	// Track successful redirect
	wsh.TrackSuccessfulRedirect(port)

	// Log successful redirect with security information
	wsh.logger.LogRedirect(host, redirectURL, clientIP, http.StatusMovedPermanently)
	wsh.logger.LogWebServiceRequest(host, clientIP, port, true)
	wsh.securityValidator.LogSecurityRequest(r, requestID, "success", port)

	// Set comprehensive security headers and redirect
	wsh.securityValidator.SetSecurityHeaders(w)
	w.Header().Set("X-Request-ID", requestID)
	http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
}

// ValidateRequest validates the request for web service mode
func (wsh *WebServiceHandler) ValidateRequest(r *http.Request) error {
	// Validate request parameters for security
	if err := wsh.securityValidator.ValidateRequestParameters(r); err != nil {
		return fmt.Errorf("invalid request parameters: %w", err)
	}

	// Validate host header for security issues
	if err := wsh.securityValidator.ValidateHostHeader(r.Host); err != nil {
		return fmt.Errorf("invalid host header: %w", err)
	}

	// Validate domain against configured patterns
	if !wsh.domainMatcher.MatchesPattern(r.Host) {
		return fmt.Errorf("host %s does not match any configured domain patterns", r.Host)
	}

	return nil
}

// ProcessRedirect processes redirect logic for web service mode
func (wsh *WebServiceHandler) ProcessRedirect(host string, configuredPorts []int) (string, int, error) {
	// Use enhanced port extraction and validation for web service mode
	port, err := extractAndValidatePort(host, configuredPorts, wsh.domainMatcher, WebServiceMode)
	if err != nil {
		return "", 0, err
	}

	// Validate redirect target for security (localhost-only with configured ports)
	if err := wsh.securityValidator.ValidateRedirectTarget(port, configuredPorts); err != nil {
		return "", 0, fmt.Errorf("invalid redirect target: %w", err)
	}

	// Generate localhost-only redirect URL
	redirectURL := fmt.Sprintf("http://localhost:%d", port)
	return redirectURL, port, nil
}

// setSecurityHeaders sets security headers for the response (deprecated - use SecurityValidator.SetSecurityHeaders)
func (wsh *WebServiceHandler) setSecurityHeaders(w http.ResponseWriter) {
	wsh.securityValidator.SetSecurityHeaders(w)
}

// StartCleanupRoutine starts a background routine to clean up old rate limiter entries
func (wsh *WebServiceHandler) StartCleanupRoutine(ctx context.Context) {
	if wsh.rateLimiter == nil {
		return
	}

	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				wsh.rateLimiter.Cleanup()
			}
		}
	}()

	if wsh.logger != nil {
		wsh.logger.LogInfo("rate_limit_cleanup", "Started rate limiter cleanup routine")
	}
}

// TrackRequest increments the request count and updates metrics
func (wsh *WebServiceHandler) TrackRequest(clientIP string) {
	wsh.metricsMutex.Lock()
	defer wsh.metricsMutex.Unlock()

	wsh.metrics.RequestCount++
	now := time.Now()
	wsh.metrics.LastRequestTime = &now

	// Track unique IPs (simplified - in production might want to use a more efficient data structure)
	// For now, we'll estimate based on request patterns
	if wsh.metrics.RequestCount%10 == 1 { // Rough estimation
		wsh.metrics.UniqueIPs++
	}
}

// TrackSuccessfulRedirect increments successful redirect count and tracks port usage
func (wsh *WebServiceHandler) TrackSuccessfulRedirect(port int) {
	wsh.metricsMutex.Lock()
	defer wsh.metricsMutex.Unlock()

	wsh.metrics.SuccessfulRedirects++
	portKey := fmt.Sprintf("%d", port)
	wsh.metrics.PortUsageStats[portKey]++
}

// TrackFailedRequest increments failed request count
func (wsh *WebServiceHandler) TrackFailedRequest() {
	wsh.metricsMutex.Lock()
	defer wsh.metricsMutex.Unlock()

	wsh.metrics.FailedRequests++
}

// TrackRateLimitedRequest increments rate limited request count
func (wsh *WebServiceHandler) TrackRateLimitedRequest() {
	wsh.metricsMutex.Lock()
	defer wsh.metricsMutex.Unlock()

	wsh.metrics.RateLimitedRequests++
}

// GetMetrics returns a copy of the current metrics
func (wsh *WebServiceHandler) GetMetrics() *WebServiceMetrics {
	wsh.metricsMutex.RLock()
	defer wsh.metricsMutex.RUnlock()

	// Create a deep copy of metrics
	metricsCopy := &WebServiceMetrics{
		DomainPatterns:      make([]string, len(wsh.metrics.DomainPatterns)),
		RequestCount:        wsh.metrics.RequestCount,
		SuccessfulRedirects: wsh.metrics.SuccessfulRedirects,
		FailedRequests:      wsh.metrics.FailedRequests,
		RateLimitedRequests: wsh.metrics.RateLimitedRequests,
		UniqueIPs:           wsh.metrics.UniqueIPs,
		PortUsageStats:      make(map[string]int64),
	}

	copy(metricsCopy.DomainPatterns, wsh.metrics.DomainPatterns)

	if wsh.metrics.LastRequestTime != nil {
		lastTime := *wsh.metrics.LastRequestTime
		metricsCopy.LastRequestTime = &lastTime
	}

	for k, v := range wsh.metrics.PortUsageStats {
		metricsCopy.PortUsageStats[k] = v
	}

	return metricsCopy
}

// SecurityValidator provides security validation functions
type SecurityValidator struct {
	logger *StructuredLogger
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator(logger *StructuredLogger) *SecurityValidator {
	return &SecurityValidator{
		logger: logger,
	}
}

// ValidateHostHeader validates the Host header for security issues
func (sv *SecurityValidator) ValidateHostHeader(host string) error {
	if host == "" {
		return fmt.Errorf("host header is empty")
	}

	// Check for excessive length (potential DoS)
	if len(host) > 253 {
		sv.logger.LogWarning("security_validation", fmt.Sprintf("host header too long: %d characters", len(host)))
		return fmt.Errorf("host header too long")
	}

	// Check for null bytes (potential injection)
	if strings.Contains(host, "\x00") {
		sv.logger.LogWarning("security_validation", "host header contains null bytes")
		return fmt.Errorf("host header contains invalid characters")
	}

	// Check for control characters
	for _, char := range host {
		if char < 32 && char != 9 { // Allow tab (9) but not other control chars
			sv.logger.LogWarning("security_validation", fmt.Sprintf("host header contains control character: %d", char))
			return fmt.Errorf("host header contains invalid characters")
		}
	}

	// Check for suspicious patterns that might indicate header injection
	suspiciousPatterns := []string{
		"\r", "\n", "\r\n", // CRLF injection
		"javascript:", "data:", "vbscript:", // Protocol injection
		"<script", "</script>", // XSS attempts
		"eval(", "alert(", // JavaScript injection
	}

	lowerHost := strings.ToLower(host)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerHost, pattern) {
			sv.logger.LogWarning("security_validation", fmt.Sprintf("host header contains suspicious pattern: %s", pattern))
			return fmt.Errorf("host header contains invalid content")
		}
	}

	return nil
}

// ValidateRedirectTarget ensures redirect targets are localhost-only and secure
func (sv *SecurityValidator) ValidateRedirectTarget(port int, configuredPorts []int) error {
	// Validate port range
	if !validatePort(port) {
		sv.logger.LogWarning("security_validation", fmt.Sprintf("port out of range: %d", port))
		return fmt.Errorf("port %d is out of valid range (1-65535)", port)
	}

	// Additional security checks for commonly restricted ports (check before configuration)
	restrictedPorts := []int{
		22,   // SSH
		23,   // Telnet
		25,   // SMTP
		53,   // DNS
		110,  // POP3
		143,  // IMAP
		993,  // IMAPS
		995,  // POP3S
		1433, // SQL Server
		1521, // Oracle
		3306, // MySQL
		5432, // PostgreSQL
		6379, // Redis
		135,  // RPC
		139,  // NetBIOS
		445,  // SMB
		1723, // PPTP
		3389, // RDP
	}

	for _, restricted := range restrictedPorts {
		if port == restricted {
			sv.logger.LogWarning("security_validation", fmt.Sprintf("redirect to restricted port attempted: %d", port))
			return fmt.Errorf("redirect to restricted port %d not allowed", port)
		}
	}

	// Ensure port is in configured list (whitelist approach)
	if !isPortConfigured(port, configuredPorts) {
		sv.logger.LogWarning("security_validation", fmt.Sprintf("port not in configured list: %d", port))
		return fmt.Errorf("port %d is not configured for redirection", port)
	}

	return nil
}

// ValidateLocalhostRedirect ensures the redirect URL is localhost-only
func (sv *SecurityValidator) ValidateLocalhostRedirect(targetURL string) error {
	if targetURL == "" {
		return fmt.Errorf("redirect URL cannot be empty")
	}

	// Check for URL length first (prevent DoS)
	if len(targetURL) > 256 {
		sv.logger.LogWarning("security_validation", fmt.Sprintf("redirect URL too long: %d characters", len(targetURL)))
		return fmt.Errorf("redirect URL too long")
	}

	// Parse the URL to validate components
	parsedURL, err := regexp.MatchString(`^https?://(?:localhost|127\.0\.0\.1|::1):\d+/?$`, targetURL)
	if err != nil {
		sv.logger.LogWarning("security_validation", fmt.Sprintf("failed to parse redirect URL: %s", targetURL))
		return fmt.Errorf("invalid redirect URL format")
	}

	if !parsedURL {
		sv.logger.LogWarning("security_validation", fmt.Sprintf("non-localhost redirect attempted: %s", targetURL))
		return fmt.Errorf("redirect must be to localhost only")
	}

	return nil
}

// ValidateRequestParameters validates request parameters for security issues
func (sv *SecurityValidator) ValidateRequestParameters(r *http.Request) error {
	// Validate request method
	if r.Method != "GET" && r.Method != "HEAD" {
		sv.logger.LogWarning("security_validation", fmt.Sprintf("invalid request method: %s", r.Method))
		return fmt.Errorf("method %s not allowed", r.Method)
	}

	// Validate User-Agent header (check for suspicious patterns)
	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		// Check for excessively long User-Agent (potential DoS)
		if len(userAgent) > 1024 {
			sv.logger.LogWarning("security_validation", fmt.Sprintf("user-agent too long: %d characters", len(userAgent)))
			return fmt.Errorf("user-agent header too long")
		}

		// Check for suspicious bot patterns
		suspiciousBots := []string{
			"sqlmap", "nikto", "nmap", "masscan", "zap", "burp",
			"w3af", "skipfish", "dirb", "dirbuster", "gobuster",
			"nuclei", "ffuf", "wfuzz", "hydra", "medusa",
		}

		lowerUA := strings.ToLower(userAgent)
		for _, bot := range suspiciousBots {
			if strings.Contains(lowerUA, bot) {
				sv.logger.LogWarning("security_validation", fmt.Sprintf("suspicious user-agent detected: %s", bot))
				return fmt.Errorf("request blocked")
			}
		}
	}

	// Validate query parameters (should be empty for redirect service)
	if len(r.URL.RawQuery) > 0 {
		sv.logger.LogWarning("security_validation", fmt.Sprintf("unexpected query parameters: %s", r.URL.RawQuery))
		return fmt.Errorf("query parameters not allowed")
	}

	// Validate request path (should be root or status)
	if r.URL.Path != "/" && r.URL.Path != "/status" && r.URL.Path != "/health" {
		sv.logger.LogWarning("security_validation", fmt.Sprintf("invalid request path: %s", r.URL.Path))
		return fmt.Errorf("path not found")
	}

	// Validate Content-Length for GET/HEAD requests (should be 0)
	if contentLength := r.Header.Get("Content-Length"); contentLength != "" && contentLength != "0" {
		sv.logger.LogWarning("security_validation", fmt.Sprintf("unexpected content-length for %s request: %s", r.Method, contentLength))
		return fmt.Errorf("content not allowed for %s requests", r.Method)
	}

	// Check for suspicious headers that might indicate attack attempts
	suspiciousHeaders := []string{
		"X-Forwarded-Host", "X-Host", "X-Original-Host", "X-Rewrite-URL",
		"X-Original-URL", "X-Override-URL", "Destination",
	}

	for _, header := range suspiciousHeaders {
		if value := r.Header.Get(header); value != "" {
			sv.logger.LogWarning("security_validation", fmt.Sprintf("suspicious header detected: %s=%s", header, value))
			return fmt.Errorf("suspicious request headers")
		}
	}

	return nil
}

// LogSecurityEvent logs security-relevant information with enhanced details
func (sv *SecurityValidator) LogSecurityEvent(eventType, clientIP, host, details string) {
	if sv.logger != nil {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		sv.logger.LogWarning("security_event", fmt.Sprintf("timestamp=%s type=%s client=%s host=%s details=%s", timestamp, eventType, clientIP, host, details))
	}
}

// LogSecurityRequest logs comprehensive security information for each request
func (sv *SecurityValidator) LogSecurityRequest(r *http.Request, requestID, result string, port int) {
	if sv.logger != nil {
		clientIP := getClientIPFromRequest(r)
		userAgent := r.Header.Get("User-Agent")
		if len(userAgent) > 100 {
			userAgent = userAgent[:100] + "..."
		}

		timestamp := time.Now().UTC().Format(time.RFC3339)
		sv.logger.LogInfo("security_request", fmt.Sprintf(
			"timestamp=%s request_id=%s client=%s host=%s method=%s user_agent=%s path=%s result=%s port=%d",
			timestamp, requestID, clientIP, r.Host, r.Method, userAgent, r.URL.Path, result, port))
	}
}

// GenerateRequestID generates a unique request ID for tracking
func (sv *SecurityValidator) GenerateRequestID() string {
	now := time.Now()
	return fmt.Sprintf("%d-%d-%d", now.UnixNano(), now.Nanosecond(), now.Unix()%1000)
}

// CreateSafeErrorResponse creates error responses that don't leak sensitive information
func (sv *SecurityValidator) CreateSafeErrorResponse(w http.ResponseWriter, r *http.Request, err error, statusCode int, requestID string) {
	clientIP := getClientIPFromRequest(r)

	// Log the actual error for debugging with request ID for correlation
	sv.logger.LogError("request_error", fmt.Sprintf("request_id=%s client=%s path=%s error=%s", requestID, clientIP, r.URL.Path, err.Error()), err)

	// Log security event for monitoring
	sv.LogSecurityEvent("error_response", clientIP, r.Host, fmt.Sprintf("status=%d request_id=%s", statusCode, requestID))

	// Return generic error messages to prevent information leakage
	var safeMessage string
	switch statusCode {
	case http.StatusBadRequest:
		safeMessage = "Bad Request"
	case http.StatusUnauthorized:
		safeMessage = "Unauthorized"
	case http.StatusForbidden:
		safeMessage = "Forbidden"
	case http.StatusNotFound:
		safeMessage = "Not Found"
	case http.StatusMethodNotAllowed:
		safeMessage = "Method Not Allowed"
	case http.StatusRequestTimeout:
		safeMessage = "Request Timeout"
	case http.StatusTooManyRequests:
		safeMessage = "Too Many Requests"
	case http.StatusInternalServerError:
		safeMessage = "Internal Server Error"
	case http.StatusBadGateway:
		safeMessage = "Bad Gateway"
	case http.StatusServiceUnavailable:
		safeMessage = "Service Unavailable"
	case http.StatusGatewayTimeout:
		safeMessage = "Gateway Timeout"
	default:
		safeMessage = "Request Error"
	}

	// Set comprehensive security headers
	sv.SetSecurityHeaders(w)

	// Add request ID to response headers for debugging (but not the error details)
	w.Header().Set("X-Request-ID", requestID)

	http.Error(w, safeMessage, statusCode)
}

// SetSecurityHeaders sets comprehensive security headers on the response
func (sv *SecurityValidator) SetSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
	w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
}

// getClientIPFromRequest extracts client IP with security considerations
func getClientIPFromRequest(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxied requests)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list and validate it
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			// Basic IP validation
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// Fall back to RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// Return RemoteAddr as-is if parsing fails
	return r.RemoteAddr
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

// handleRedirect handles HTTP requests and performs port-based redirects using mode-aware handler
func (s *PortRedirectService) handleRedirect(w http.ResponseWriter, r *http.Request) {
	// Use the mode-aware handler to process the request
	if s.requestHandler != nil {
		s.requestHandler.HandleRequest(w, r)
	} else {
		// Fallback to legacy handling if handler is not initialized
		s.structuredLogger.LogError("handler_error", "Request handler not initialized, using fallback", nil)
		s.handleRedirectLegacy(w, r)
	}
}

// handleRedirectLegacy provides fallback handling for backward compatibility
func (s *PortRedirectService) handleRedirectLegacy(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	clientIP := getClientIPFromRequest(r)

	// Log the incoming request with security-relevant information
	s.structuredLogger.LogInfo("request_received", fmt.Sprintf("host=%s client=%s method=%s user_agent=%s",
		host, clientIP, r.Method, r.Header.Get("User-Agent")))

	// Generate request ID for tracking
	requestID := s.securityValidator.GenerateRequestID()

	// Validate request parameters for security
	if err := s.securityValidator.ValidateRequestParameters(r); err != nil {
		s.securityValidator.LogSecurityEvent("invalid_request", clientIP, host, err.Error())
		s.securityValidator.CreateSafeErrorResponse(w, r, err, http.StatusBadRequest, requestID)
		s.structuredLogger.LogRedirect(host, "none", clientIP, http.StatusBadRequest)
		return
	}

	// Validate host header for security issues
	if err := s.securityValidator.ValidateHostHeader(host); err != nil {
		s.securityValidator.LogSecurityEvent("invalid_host", clientIP, host, err.Error())
		s.securityValidator.CreateSafeErrorResponse(w, r, err, http.StatusBadRequest, requestID)
		s.structuredLogger.LogRedirect(host, "none", clientIP, http.StatusBadRequest)
		return
	}

	// Extract port from host header
	port, extracted := extractPortFromHost(host)
	if !extracted {
		// Host doesn't match expected format, return 404
		s.structuredLogger.LogError("port_extraction", fmt.Sprintf("Invalid host format: %s", host), nil)
		s.securityValidator.CreateSafeErrorResponse(w, r, fmt.Errorf("invalid host format"), http.StatusNotFound, requestID)
		s.structuredLogger.LogRedirect(host, "none", clientIP, http.StatusNotFound)
		return
	}

	// Validate redirect target for security (localhost-only)
	if err := s.securityValidator.ValidateRedirectTarget(port, s.config.Ports); err != nil {
		s.securityValidator.LogSecurityEvent("invalid_redirect_target", clientIP, host, err.Error())
		s.securityValidator.CreateSafeErrorResponse(w, r, err, http.StatusBadRequest, requestID)
		s.structuredLogger.LogRedirect(host, "none", clientIP, http.StatusBadRequest)
		return
	}

	// Check if port is configured
	if !isPortConfigured(port, s.config.Ports) {
		// Port is not in configuration, return 404
		s.structuredLogger.LogWarning("port_not_configured", fmt.Sprintf("Port %d not in configuration", port))
		s.securityValidator.CreateSafeErrorResponse(w, r, fmt.Errorf("port not configured"), http.StatusNotFound, requestID)
		s.structuredLogger.LogRedirect(host, "none", clientIP, http.StatusNotFound)
		return
	}

	// Generate localhost-only redirect URL
	redirectURL := fmt.Sprintf("http://localhost:%d", port)

	// Log the successful redirect with security information
	s.structuredLogger.LogRedirect(host, redirectURL, clientIP, http.StatusMovedPermanently)
	s.structuredLogger.LogInfo("redirect_success", fmt.Sprintf("host=%s target=%s client=%s", host, redirectURL, clientIP))

	// Set security headers before redirect
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	// Send HTTP 301 permanent redirect
	http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
}

// getClientIP extracts the client IP address from the request (deprecated, use getClientIPFromRequest)
func (s *PortRedirectService) getClientIP(r *http.Request) string {
	return getClientIPFromRequest(r)
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

	// Build web service metrics
	webServiceMetricsHTML := ""
	if status.DeploymentMode == "web" && status.WebServiceMetrics != nil {
		metrics := status.WebServiceMetrics

		// Format domain patterns
		domainPatternsStr := ""
		for i, pattern := range metrics.DomainPatterns {
			if i > 0 {
				domainPatternsStr += ", "
			}
			domainPatternsStr += pattern
		}

		// Format port usage stats
		portUsageHTML := ""
		if len(metrics.PortUsageStats) > 0 {
			portUsageHTML = "<h4>Port Usage Statistics:</h4><ul>"
			for port, count := range metrics.PortUsageStats {
				portUsageHTML += fmt.Sprintf("<li>Port %s: %d requests</li>", port, count)
			}
			portUsageHTML += "</ul>"
		}

		// Format last request time
		lastRequestStr := "Never"
		if metrics.LastRequestTime != nil {
			lastRequestStr = metrics.LastRequestTime.Format("2006-01-02 15:04:05")
		}

		webServiceMetricsHTML = fmt.Sprintf(`
		<div class="section">
			<h2>Web Service Metrics</h2>
			<div class="info-grid">
				<div class="info-label">Domain Patterns:</div>
				<div class="ports">%s</div>
				<div class="info-label">Total Requests:</div>
				<div>%d</div>
				<div class="info-label">Successful Redirects:</div>
				<div class="status-ok">%d</div>
				<div class="info-label">Failed Requests:</div>
				<div class="status-error">%d</div>
				<div class="info-label">Rate Limited:</div>
				<div>%d</div>
				<div class="info-label">Unique IPs:</div>
				<div>%d</div>
				<div class="info-label">Last Request:</div>
				<div>%s</div>
			</div>
			%s
		</div>`, domainPatternsStr, metrics.RequestCount, metrics.SuccessfulRedirects,
			metrics.FailedRequests, metrics.RateLimitedRequests, metrics.UniqueIPs,
			lastRequestStr, portUsageHTML)
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
                <div class="info-label">Deployment Mode:</div>
                <div><strong>%s</strong></div>
                <div class="info-label">Uptime:</div>
                <div>%s</div>
                <div class="info-label">Config Loaded:</div>
                <div>%s</div>
                <div class="info-label">Configured Ports:</div>
                <div class="ports">%s</div>
            </div>
        </div>

        %s

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
		status.DeploymentMode,
		uptimeStr,
		configLoadedStr,
		portsStr,
		webServiceMetricsHTML,
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
		fmt.Fprintf(w, ",\n    \"deployment_mode\": \"%s\"", v.DeploymentMode)
		if v.WebServiceMetrics != nil {
			fmt.Fprint(w, ",\n    \"web_service_metrics\": ")
			s.writeJSONValue(w, v.WebServiceMetrics)
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
	case *WebServiceMetrics:
		if v == nil {
			fmt.Fprint(w, "null")
			return
		}
		fmt.Fprint(w, "{\n")
		fmt.Fprint(w, "      \"domain_patterns\": [")
		for i, pattern := range v.DomainPatterns {
			if i > 0 {
				fmt.Fprint(w, ", ")
			}
			fmt.Fprintf(w, "\"%s\"", strings.ReplaceAll(pattern, "\"", "\\\""))
		}
		fmt.Fprint(w, "],\n")
		fmt.Fprintf(w, "      \"request_count\": %d,\n", v.RequestCount)
		fmt.Fprintf(w, "      \"successful_redirects\": %d,\n", v.SuccessfulRedirects)
		fmt.Fprintf(w, "      \"failed_requests\": %d,\n", v.FailedRequests)
		fmt.Fprintf(w, "      \"rate_limited_requests\": %d,\n", v.RateLimitedRequests)
		fmt.Fprintf(w, "      \"unique_ips\": %d", v.UniqueIPs)
		if v.LastRequestTime != nil {
			fmt.Fprintf(w, ",\n      \"last_request_time\": \"%s\"", v.LastRequestTime.Format(time.RFC3339))
		}
		if len(v.PortUsageStats) > 0 {
			fmt.Fprint(w, ",\n      \"port_usage_stats\": {")
			first := true
			for port, count := range v.PortUsageStats {
				if !first {
					fmt.Fprint(w, ", ")
				}
				first = false
				fmt.Fprintf(w, "\"%s\": %d", port, count)
			}
			fmt.Fprint(w, "}")
		}
		fmt.Fprint(w, "\n    }")
	default:
		fmt.Fprintf(w, "null")
	}
}

// handleHealth handles requests to the /health endpoint for load balancer health checks
func (s *PortRedirectService) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Simple health check - return 200 if service is running
	// This is suitable for load balancers that just need to know if the service is up

	status := s.GetServiceStatus()

	// Determine health status
	isHealthy := true
	healthStatus := "healthy"

	// Check for critical errors
	if status.LastError != "" {
		isHealthy = false
		healthStatus = "unhealthy"
	}

	// For local mode, check hosts file status
	if s.config.DeploymentMode == LocalMode && !status.HostsStatus.EntriesValid {
		isHealthy = false
		healthStatus = "degraded"
	}

	// Check if JSON format is requested
	if r.URL.Query().Get("format") == "json" || r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")

		if isHealthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		healthResponse := map[string]interface{}{
			"status":          healthStatus,
			"deployment_mode": status.DeploymentMode,
			"uptime":          status.Uptime.String(),
			"timestamp":       time.Now().Format(time.RFC3339),
		}

		// Add mode-specific health info
		if s.config.DeploymentMode == WebServiceMode && status.WebServiceMetrics != nil {
			healthResponse["request_count"] = status.WebServiceMetrics.RequestCount
			healthResponse["domain_patterns_count"] = len(status.WebServiceMetrics.DomainPatterns)
		} else {
			healthResponse["hosts_valid"] = status.HostsStatus.EntriesValid
			healthResponse["backup_exists"] = status.HostsStatus.BackupExists
		}

		s.writeJSON(w, healthResponse)
	} else {
		// Simple text response for basic health checks
		w.Header().Set("Content-Type", "text/plain")

		if isHealthy {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "OK - %s mode - uptime: %s\n", status.DeploymentMode, status.Uptime.String())
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "UNHEALTHY - %s - %s\n", healthStatus, status.LastError)
		}
	}
}

// GetServiceStatus collects and returns the current service status
func (s *PortRedirectService) GetServiceStatus() *ServiceStatus {
	// Calculate uptime
	uptime := time.Since(s.startTime)

	// Check hosts file validity
	hostsStatus := s.getHostsFileStatus()

	// Get web service metrics if in web service mode
	var webServiceMetrics *WebServiceMetrics
	if s.config.DeploymentMode == WebServiceMode && s.requestHandler != nil && s.requestHandler.webHandler != nil {
		if webHandler, ok := s.requestHandler.webHandler.(*WebServiceHandler); ok {
			webServiceMetrics = webHandler.GetMetrics()
		}
	}

	return &ServiceStatus{
		Uptime:            uptime,
		ConfigLoaded:      s.configLoaded,
		PortsConfigured:   s.config.Ports,
		HostsStatus:       hostsStatus,
		LastError:         s.lastError,
		DeploymentMode:    s.config.DeploymentMode.String(),
		WebServiceMetrics: webServiceMetrics,
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

	// Health check endpoint
	mux.HandleFunc("/health", s.handleHealth)

	// Default handler for all other requests (redirect handler)
	mux.HandleFunc("/", s.handleRedirect)

	s.server.Handler = mux
}

// Start starts the HTTP server and begins listening for requests
func (s *PortRedirectService) Start() error {
	// Log startup with mode-specific information
	if s.config.DeploymentMode == WebServiceMode {
		s.structuredLogger.LogInfo("server_start", fmt.Sprintf("Starting HTTP server in web service mode on port %d", s.config.WebServicePort))
		s.structuredLogger.LogInfo("web_service_config", fmt.Sprintf("Domain patterns: %v, Rate limiting: %v",
			s.config.DomainPatterns, s.config.EnableRateLimit))
	} else {
		s.structuredLogger.LogInfo("server_start", "Starting HTTP server in local mode on port 80")
	}

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

	// Start rate limiter cleanup routine for web service mode
	if s.config.DeploymentMode == WebServiceMode && s.requestHandler != nil && s.requestHandler.webHandler != nil {
		if webServiceHandler, ok := s.requestHandler.webHandler.(*WebServiceHandler); ok {
			ctx := context.Background() // TODO: Use proper context from service lifecycle
			webServiceHandler.StartCleanupRoutine(ctx)
		}
	}

	// Log successful startup with deployment mode information
	if s.config.DeploymentMode == WebServiceMode {
		s.structuredLogger.LogInfo("server_started", fmt.Sprintf("HTTP server started successfully in web service mode on %s", s.server.Addr))
		s.structuredLogger.LogInfo("web_service_ready", fmt.Sprintf("Ready to handle requests for domains: %v", s.config.DomainPatterns))
	} else {
		s.structuredLogger.LogInfo("server_started", "HTTP server started successfully in local mode on port 80")
	}

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

	// Mode-specific cleanup
	if s.config.DeploymentMode == LocalMode && s.hostsManager != nil {
		// Local mode: remove hosts file entries
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
	} else {
		// Web service mode: no hosts file cleanup needed
		s.structuredLogger.LogInfo("cleanup_web_service", "Web service mode - no hosts file cleanup required")
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

	// Determine server address based on deployment mode
	var serverAddr string
	var hostsManager *HostsManager

	if config.DeploymentMode == WebServiceMode {
		// Web service mode - use configurable port
		serverAddr = fmt.Sprintf(":%d", config.WebServicePort)
		// No hosts manager needed for web service mode
		hostsManager = nil
	} else {
		// Local mode - use port 80 and create hosts manager
		serverAddr = ":80"
		hostsFilePath := DefaultHostsPath
		if config.DeploymentConfig != nil && config.DeploymentConfig.LocalConfig != nil {
			hostsFilePath = config.DeploymentConfig.LocalConfig.HostsFilePath
		}
		hostsManager = NewHostsManager(hostsFilePath, config.HostsBackupPath)
	}

	structuredLogger := NewStructuredLogger(logger)
	securityValidator := NewSecurityValidator(structuredLogger)

	service := &PortRedirectService{
		config:            config,
		logger:            logger,
		structuredLogger:  structuredLogger,
		logFileManager:    logFileManager,
		hostsManager:      hostsManager,
		securityValidator: securityValidator,
		server: &http.Server{
			Addr: serverAddr,
		},
		startTime:    now,
		configLoaded: now,
	}

	// Initialize mode-aware request handler
	service.requestHandler = NewModeAwareHandler(config.DeploymentMode, config, structuredLogger, securityValidator)

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

	// Load deployment configuration to determine mode
	deploymentConfig, err := parseDeploymentConfig(DefaultConfigPath)
	if err != nil {
		structuredLogger.LogError("startup", "Failed to load deployment configuration", err)
		os.Exit(1)
	}

	// Log deployment mode
	structuredLogger.LogInfo("deployment_mode", fmt.Sprintf("Running in %s mode", deploymentConfig.Mode.String()))

	// Mode-specific privilege and instance checks
	if deploymentConfig.Mode == LocalMode {
		// Check if we have the required privileges for local mode
		if err := checkPrivileges(); err != nil {
			structuredLogger.LogError("startup", "Insufficient privileges for local mode", err)
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Check if another instance is already running
		if err := checkSingleInstance(); err != nil {
			structuredLogger.LogError("startup", "Service is already running", err)
			os.Exit(0)
		}
	} else {
		// Web service mode - log that we're skipping privilege checks
		structuredLogger.LogInfo("startup", "Web service mode - skipping privilege and single instance checks")
	}

	// Load port configuration
	ports, err := loadConfig(DefaultConfigPath)
	if err != nil {
		structuredLogger.LogError("startup", "Failed to load port configuration", err)
		os.Exit(1)
	}

	// Create enhanced service configuration
	config := &Config{
		Ports:            ports,
		ConfigFilePath:   DefaultConfigPath,
		HostsBackupPath:  DefaultBackupPath,
		LogLevel:         "INFO",
		DeploymentMode:   deploymentConfig.Mode,
		DeploymentConfig: deploymentConfig,
	}

	// Set mode-specific configuration
	if deploymentConfig.Mode == WebServiceMode {
		config.WebServicePort = deploymentConfig.WebConfig.Port
		config.DomainPatterns = deploymentConfig.WebConfig.DomainPatterns
		config.EnableRateLimit = deploymentConfig.WebConfig.RateLimit.Enabled
		config.RateLimitRPS = deploymentConfig.WebConfig.RateLimit.RPS

		// Validate web service configuration
		if len(config.DomainPatterns) == 0 {
			structuredLogger.LogError("startup", "Web service mode requires domain patterns", nil)
			os.Exit(1)
		}
	}

	// Log the actual port count now that we have it
	structuredLogger.LogStartup("1.0.0", DefaultConfigPath, len(ports))

	// Create service instance
	service := NewPortRedirectService(config, logger, logFileManager)

	// Mode-specific initialization
	if config.DeploymentMode == LocalMode {
		// Local mode: setup hosts file management
		if service.hostsManager != nil {
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
		}
	} else {
		// Web service mode: validate domain patterns and log configuration
		service.structuredLogger.LogInfo("web_service_init", fmt.Sprintf("Initializing web service mode with %d domain patterns", len(config.DomainPatterns)))
		for i, pattern := range config.DomainPatterns {
			service.structuredLogger.LogInfo("domain_pattern", fmt.Sprintf("Pattern %d: %s", i+1, pattern))
		}

		if config.EnableRateLimit {
			service.structuredLogger.LogInfo("rate_limit_init", fmt.Sprintf("Rate limiting enabled: %d requests per second", config.RateLimitRPS))
		}
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
