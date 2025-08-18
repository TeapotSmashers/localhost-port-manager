# Design Document

## Overview

This design extends the existing port redirect service to support deployment as a web service while maintaining backward compatibility with the local mode. The service will operate in two distinct modes: **Local Mode** (current functionality) and **Web Service Mode** (new functionality). The design leverages the existing HTTP server architecture and adds configuration-driven mode switching, domain pattern matching, and web-specific request handling.

## Architecture

### High-Level Architecture

```mermaid
graph TB
    A[Configuration Loader] --> B[Mode Detector]
    B --> C{Deployment Mode}
    C -->|Local| D[Local Mode Handler]
    C -->|Web Service| E[Web Service Handler]
    
    D --> F[Hosts Manager]
    D --> G[Port 80 Listener]
    
    E --> H[Configurable Port Listener]
    E --> I[Domain Pattern Matcher]
    
    F --> J[/etc/hosts Modification]
    G --> K[HTTP Redirect Handler]
    H --> K
    I --> K
    
    K --> L[Localhost Redirect Response]
```

### Component Interaction

The service maintains a single HTTP server instance but adapts its behavior based on the deployment mode:

1. **Configuration Phase**: Determines deployment mode and loads appropriate settings
2. **Initialization Phase**: Sets up mode-specific components (hosts manager for local, domain matcher for web)
3. **Request Processing Phase**: Routes requests through mode-appropriate handlers
4. **Response Phase**: Generates localhost redirects with proper validation

## Components and Interfaces

### 1. Deployment Mode Manager

**Purpose**: Manages the detection and configuration of deployment modes.

```go
type DeploymentMode int

const (
    LocalMode DeploymentMode = iota
    WebServiceMode
)

type DeploymentConfig struct {
    Mode            DeploymentMode
    WebServicePort  int
    DomainPatterns  []string
    LocalConfig     *LocalModeConfig
    WebConfig       *WebServiceConfig
}

type ModeManager interface {
    DetectMode(configPath string) (DeploymentMode, error)
    LoadModeConfig(mode DeploymentMode, configPath string) (*DeploymentConfig, error)
    ValidateConfig(config *DeploymentConfig) error
}
```

**Key Responsibilities**:
- Parse configuration files to determine deployment mode
- Load mode-specific configuration parameters
- Validate configuration consistency and completeness
- Provide fallback defaults for missing configuration

### 2. Enhanced Configuration System

**Purpose**: Extends the existing configuration system to support web service parameters.

```go
type Config struct {
    // Existing fields
    Ports           []int
    ConfigFilePath  string
    HostsBackupPath string
    LogLevel        string
    
    // New fields for web service mode
    DeploymentMode  DeploymentMode
    WebServicePort  int
    DomainPatterns  []string
    EnableRateLimit bool
    RateLimitRPS    int
}
```

**Configuration File Format**:
```ini
# Deployment mode: local or web
mode=web

# Web service specific settings (only used in web mode)
web_port=8080
domain_patterns=*.sankalpmukim.dev,*.example.com

# Rate limiting (optional)
enable_rate_limit=true
rate_limit_rps=100

# Port configuration (used in both modes)
3000
8080
5173
9000
```

### 3. Domain Pattern Matcher

**Purpose**: Handles domain pattern matching and port extraction for web service mode.

```go
type DomainMatcher interface {
    AddPattern(pattern string) error
    MatchesPattern(host string) bool
    ExtractPort(host string) (int, bool)
    ValidatePatterns() error
}

type PatternMatcher struct {
    patterns []*regexp.Regexp
    logger   *StructuredLogger
}
```

**Key Features**:
- Support for wildcard patterns (`*.sankalpmukim.dev`)
- Efficient regex-based matching
- Port extraction from subdomain format (`3000.sankalpmukim.dev`)
- Pattern validation and compilation

### 4. Enhanced Request Handler

**Purpose**: Routes requests based on deployment mode and handles web service specific logic.

```go
type RequestHandler interface {
    HandleRequest(w http.ResponseWriter, r *http.Request)
    ValidateRequest(r *http.Request) error
    ProcessRedirect(host string, configuredPorts []int) (string, int, error)
}

type ModeAwareHandler struct {
    mode           DeploymentMode
    localHandler   *LocalHandler
    webHandler     *WebServiceHandler
    logger         *StructuredLogger
}
```

**Request Processing Flow**:
1. **Mode Detection**: Determine which handler to use based on configuration
2. **Request Validation**: Validate host header format and extract components
3. **Port Extraction**: Extract port number using mode-appropriate logic
4. **Port Validation**: Ensure port is in configured list and valid range
5. **Redirect Generation**: Create localhost redirect URL
6. **Response**: Send HTTP 301 redirect with proper headers

### 5. Web Service Handler

**Purpose**: Handles web service specific request processing and domain validation.

```go
type WebServiceHandler struct {
    domainMatcher    DomainMatcher
    configuredPorts  []int
    rateLimiter     *RateLimiter
    logger          *StructuredLogger
}

func (wsh *WebServiceHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
    // 1. Validate domain against patterns
    // 2. Extract port from subdomain
    // 3. Validate port against configuration
    // 4. Apply rate limiting if enabled
    // 5. Generate and send redirect
}
```

### 6. Rate Limiter (Optional)

**Purpose**: Prevents abuse by limiting requests per IP address.

```go
type RateLimiter interface {
    Allow(clientIP string) bool
    Configure(rps int, burst int)
    Cleanup() // Remove old entries
}

type IPRateLimiter struct {
    limiters map[string]*time.Ticker
    rps      int
    burst    int
    mutex    sync.RWMutex
}
```

## Data Models

### Configuration Model

```go
type WebServiceConfig struct {
    Port           int      `json:"port"`
    DomainPatterns []string `json:"domain_patterns"`
    RateLimit      struct {
        Enabled bool `json:"enabled"`
        RPS     int  `json:"rps"`
        Burst   int  `json:"burst"`
    } `json:"rate_limit"`
}

type LocalModeConfig struct {
    HostsFilePath   string `json:"hosts_file_path"`
    BackupPath      string `json:"backup_path"`
    ListenPort      int    `json:"listen_port"`
}
```

### Request Processing Model

```go
type RedirectRequest struct {
    OriginalHost   string
    ClientIP       string
    RequestedPort  int
    TargetURL      string
    ProcessingMode DeploymentMode
    Timestamp      time.Time
}

type RedirectResponse struct {
    StatusCode    int
    TargetURL     string
    ErrorMessage  string
    ProcessingTime time.Duration
}
```

## Error Handling

### Error Categories

1. **Configuration Errors**:
   - Invalid deployment mode
   - Missing required configuration
   - Invalid domain patterns
   - Port conflicts

2. **Request Processing Errors**:
   - Invalid host format
   - Domain pattern mismatch
   - Port not configured
   - Rate limit exceeded

3. **System Errors**:
   - Network binding failures
   - File system access issues
   - Resource exhaustion

### Error Response Strategy

```go
type ErrorHandler struct {
    logger *StructuredLogger
}

func (eh *ErrorHandler) HandleError(w http.ResponseWriter, r *http.Request, err error) {
    switch err.(type) {
    case *ConfigurationError:
        http.Error(w, "Service Configuration Error", http.StatusInternalServerError)
    case *ValidationError:
        http.Error(w, err.Error(), http.StatusBadRequest)
    case *NotFoundError:
        http.Error(w, err.Error(), http.StatusNotFound)
    case *RateLimitError:
        http.Error(w, "Rate Limit Exceeded", http.StatusTooManyRequests)
    default:
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
    }
    
    eh.logger.LogError("request_error", err.Error(), err)
}
```

## Testing Strategy

### Unit Testing

1. **Configuration Loading Tests**:
   - Valid configuration parsing
   - Invalid configuration handling
   - Mode detection accuracy
   - Default value application

2. **Domain Pattern Matching Tests**:
   - Pattern compilation and validation
   - Host matching accuracy
   - Port extraction correctness
   - Edge case handling

3. **Request Processing Tests**:
   - Mode-specific request routing
   - Port validation logic
   - Redirect URL generation
   - Error response formatting

### Integration Testing

1. **End-to-End Request Flow**:
   - Local mode request processing
   - Web service mode request processing
   - Configuration hot-reloading
   - Graceful shutdown behavior

2. **Cross-Mode Compatibility**:
   - Configuration migration
   - Service restart behavior
   - Backward compatibility verification

### Performance Testing

1. **Load Testing**:
   - Concurrent request handling
   - Memory usage under load
   - Response time consistency
   - Rate limiting effectiveness

2. **Stress Testing**:
   - Resource exhaustion scenarios
   - Invalid request flooding
   - Configuration change impact
   - Recovery behavior

## Security Considerations

### Input Validation

1. **Host Header Validation**:
   - Strict format checking
   - Length limitations
   - Character set restrictions
   - Injection prevention

2. **Port Number Validation**:
   - Range enforcement (1-65535)
   - Configuration list verification
   - Numeric validation
   - Overflow prevention

### Access Control

1. **Domain Restrictions**:
   - Pattern-based access control
   - Whitelist enforcement
   - Subdomain validation
   - TLD verification

2. **Rate Limiting**:
   - Per-IP request limiting
   - Burst protection
   - Cleanup mechanisms
   - Memory management

### Redirect Safety

1. **Target Validation**:
   - Localhost-only redirects
   - Port range enforcement
   - URL construction safety
   - Protocol restrictions

2. **Response Headers**:
   - Security header inclusion
   - Cache control settings
   - CORS policy enforcement
   - Content type specification

## Deployment Considerations

### Local Mode Deployment

- Requires root privileges for port 80 and /etc/hosts modification
- System service integration (systemd/launchd)
- Automatic startup configuration
- Log file management and rotation

### Web Service Mode Deployment

- Standard user privileges sufficient
- Configurable port binding (typically 8080 or 3000)
- Container-friendly architecture
- External load balancer compatibility
- Health check endpoint support

### Configuration Management

- Environment variable support
- Configuration file hot-reloading
- Validation and error reporting
- Migration assistance tools

This design maintains the existing architecture's strengths while adding the flexibility needed for web service deployment. The mode-based approach ensures clean separation of concerns and maintains backward compatibility with existing local installations.