package main

import (
	"log"
	"net/http"
	"os"
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
	server       *http.Server
	config       *Config
	hostsManager *HostsManager
	logger       *log.Logger
}

// HostsManager manages /etc/hosts file entries
type HostsManager struct {
	hostsFilePath  string
	backupPath     string
	managedEntries []string
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

func main() {
	// TODO: Initialize service components
	// This will be implemented in subsequent tasks
	logger := log.New(os.Stdout, "[PORT-REDIRECT] ", log.LstdFlags)
	logger.Println("Port Redirect Service starting...")
}
